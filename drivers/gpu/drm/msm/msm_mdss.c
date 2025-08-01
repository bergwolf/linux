/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2018, The Linux Foundation
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/interconnect.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/irqdesc.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include <linux/soc/qcom/ubwc.h>

#include "msm_kms.h"

#include <generated/mdss.xml.h>

#define MIN_IB_BW	400000000UL /* Min ib vote 400MB */

struct msm_mdss_data {
	u32 reg_bus_bw;
};

struct msm_mdss {
	struct device *dev;

	void __iomem *mmio;
	struct clk_bulk_data *clocks;
	size_t num_clocks;
	bool is_mdp5;
	struct {
		unsigned long enabled_mask;
		struct irq_domain *domain;
	} irq_controller;
	const struct qcom_ubwc_cfg_data *mdss_data;
	u32 reg_bus_bw;
	struct icc_path *mdp_path[2];
	u32 num_mdp_paths;
	struct icc_path *reg_bus_path;
};

static int msm_mdss_parse_data_bus_icc_path(struct device *dev,
					    struct msm_mdss *msm_mdss)
{
	struct icc_path *path0;
	struct icc_path *path1;
	struct icc_path *reg_bus_path;

	path0 = devm_of_icc_get(dev, "mdp0-mem");
	if (IS_ERR_OR_NULL(path0))
		return PTR_ERR_OR_ZERO(path0);

	msm_mdss->mdp_path[0] = path0;
	msm_mdss->num_mdp_paths = 1;

	path1 = devm_of_icc_get(dev, "mdp1-mem");
	if (!IS_ERR_OR_NULL(path1)) {
		msm_mdss->mdp_path[1] = path1;
		msm_mdss->num_mdp_paths++;
	}

	reg_bus_path = of_icc_get(dev, "cpu-cfg");
	if (!IS_ERR_OR_NULL(reg_bus_path))
		msm_mdss->reg_bus_path = reg_bus_path;

	return 0;
}

static void msm_mdss_irq(struct irq_desc *desc)
{
	struct msm_mdss *msm_mdss = irq_desc_get_handler_data(desc);
	struct irq_chip *chip = irq_desc_get_chip(desc);
	u32 interrupts;

	chained_irq_enter(chip, desc);

	interrupts = readl_relaxed(msm_mdss->mmio + REG_MDSS_HW_INTR_STATUS);

	while (interrupts) {
		irq_hw_number_t hwirq = fls(interrupts) - 1;
		int rc;

		rc = generic_handle_domain_irq(msm_mdss->irq_controller.domain,
					       hwirq);
		if (rc < 0) {
			dev_err(msm_mdss->dev, "handle irq fail: irq=%lu rc=%d\n",
				  hwirq, rc);
			break;
		}

		interrupts &= ~(1 << hwirq);
	}

	chained_irq_exit(chip, desc);
}

static void msm_mdss_irq_mask(struct irq_data *irqd)
{
	struct msm_mdss *msm_mdss = irq_data_get_irq_chip_data(irqd);

	/* memory barrier */
	smp_mb__before_atomic();
	clear_bit(irqd->hwirq, &msm_mdss->irq_controller.enabled_mask);
	/* memory barrier */
	smp_mb__after_atomic();
}

static void msm_mdss_irq_unmask(struct irq_data *irqd)
{
	struct msm_mdss *msm_mdss = irq_data_get_irq_chip_data(irqd);

	/* memory barrier */
	smp_mb__before_atomic();
	set_bit(irqd->hwirq, &msm_mdss->irq_controller.enabled_mask);
	/* memory barrier */
	smp_mb__after_atomic();
}

static struct irq_chip msm_mdss_irq_chip = {
	.name = "msm_mdss",
	.irq_mask = msm_mdss_irq_mask,
	.irq_unmask = msm_mdss_irq_unmask,
};

static struct lock_class_key msm_mdss_lock_key, msm_mdss_request_key;

static int msm_mdss_irqdomain_map(struct irq_domain *domain,
		unsigned int irq, irq_hw_number_t hwirq)
{
	struct msm_mdss *msm_mdss = domain->host_data;

	irq_set_lockdep_class(irq, &msm_mdss_lock_key, &msm_mdss_request_key);
	irq_set_chip_and_handler(irq, &msm_mdss_irq_chip, handle_level_irq);

	return irq_set_chip_data(irq, msm_mdss);
}

static const struct irq_domain_ops msm_mdss_irqdomain_ops = {
	.map = msm_mdss_irqdomain_map,
	.xlate = irq_domain_xlate_onecell,
};

static int _msm_mdss_irq_domain_add(struct msm_mdss *msm_mdss)
{
	struct device *dev;
	struct irq_domain *domain;

	dev = msm_mdss->dev;

	domain = irq_domain_create_linear(of_fwnode_handle(dev->of_node), 32,
			&msm_mdss_irqdomain_ops, msm_mdss);
	if (!domain) {
		dev_err(dev, "failed to add irq_domain\n");
		return -EINVAL;
	}

	msm_mdss->irq_controller.enabled_mask = 0;
	msm_mdss->irq_controller.domain = domain;

	return 0;
}

static void msm_mdss_setup_ubwc_dec_20(struct msm_mdss *msm_mdss)
{
	const struct qcom_ubwc_cfg_data *data = msm_mdss->mdss_data;
	u32 value = MDSS_UBWC_STATIC_UBWC_SWIZZLE(data->ubwc_swizzle) |
		    MDSS_UBWC_STATIC_HIGHEST_BANK_BIT(data->highest_bank_bit - 13);

	if (data->ubwc_bank_spread)
		value |= MDSS_UBWC_STATIC_UBWC_BANK_SPREAD;

	if (data->ubwc_enc_version == UBWC_1_0)
		value |= MDSS_UBWC_STATIC_UBWC_MIN_ACC_LEN(1);

	writel_relaxed(value, msm_mdss->mmio + REG_MDSS_UBWC_STATIC);
}

static void msm_mdss_setup_ubwc_dec_30(struct msm_mdss *msm_mdss)
{
	const struct qcom_ubwc_cfg_data *data = msm_mdss->mdss_data;
	u32 value = MDSS_UBWC_STATIC_UBWC_SWIZZLE(data->ubwc_swizzle & 0x1) |
		    MDSS_UBWC_STATIC_HIGHEST_BANK_BIT(data->highest_bank_bit - 13);

	if (data->macrotile_mode)
		value |= MDSS_UBWC_STATIC_MACROTILE_MODE;

	if (data->ubwc_enc_version == UBWC_3_0)
		value |= MDSS_UBWC_STATIC_UBWC_AMSBC;

	if (data->ubwc_enc_version == UBWC_1_0)
		value |= MDSS_UBWC_STATIC_UBWC_MIN_ACC_LEN(1);

	writel_relaxed(value, msm_mdss->mmio + REG_MDSS_UBWC_STATIC);
}

static void msm_mdss_setup_ubwc_dec_40(struct msm_mdss *msm_mdss)
{
	const struct qcom_ubwc_cfg_data *data = msm_mdss->mdss_data;
	u32 value = MDSS_UBWC_STATIC_UBWC_SWIZZLE(data->ubwc_swizzle) |
		    MDSS_UBWC_STATIC_HIGHEST_BANK_BIT(data->highest_bank_bit - 13);

	if (data->ubwc_bank_spread)
		value |= MDSS_UBWC_STATIC_UBWC_BANK_SPREAD;

	if (data->macrotile_mode)
		value |= MDSS_UBWC_STATIC_MACROTILE_MODE;

	writel_relaxed(value, msm_mdss->mmio + REG_MDSS_UBWC_STATIC);

	if (data->ubwc_enc_version == UBWC_3_0) {
		writel_relaxed(1, msm_mdss->mmio + REG_MDSS_UBWC_CTRL_2);
		writel_relaxed(0, msm_mdss->mmio + REG_MDSS_UBWC_PREDICTION_MODE);
	} else {
		if (data->ubwc_dec_version == UBWC_4_3)
			writel_relaxed(3, msm_mdss->mmio + REG_MDSS_UBWC_CTRL_2);
		else
			writel_relaxed(2, msm_mdss->mmio + REG_MDSS_UBWC_CTRL_2);
		writel_relaxed(1, msm_mdss->mmio + REG_MDSS_UBWC_PREDICTION_MODE);
	}
}

static void msm_mdss_setup_ubwc_dec_50(struct msm_mdss *msm_mdss)
{
	const struct qcom_ubwc_cfg_data *data = msm_mdss->mdss_data;
	u32 value = MDSS_UBWC_STATIC_UBWC_SWIZZLE(data->ubwc_swizzle) |
		    MDSS_UBWC_STATIC_HIGHEST_BANK_BIT(data->highest_bank_bit);

	if (data->ubwc_bank_spread)
		value |= MDSS_UBWC_STATIC_UBWC_BANK_SPREAD;

	if (data->macrotile_mode)
		value |= MDSS_UBWC_STATIC_MACROTILE_MODE;

	writel_relaxed(value, msm_mdss->mmio + REG_MDSS_UBWC_STATIC);

	writel_relaxed(4, msm_mdss->mmio + REG_MDSS_UBWC_CTRL_2);
	writel_relaxed(1, msm_mdss->mmio + REG_MDSS_UBWC_PREDICTION_MODE);
}

static int msm_mdss_enable(struct msm_mdss *msm_mdss)
{
	int ret, i;

	/*
	 * Several components have AXI clocks that can only be turned on if
	 * the interconnect is enabled (non-zero bandwidth). Let's make sure
	 * that the interconnects are at least at a minimum amount.
	 */
	for (i = 0; i < msm_mdss->num_mdp_paths; i++)
		icc_set_bw(msm_mdss->mdp_path[i], 0, Bps_to_icc(MIN_IB_BW));

	icc_set_bw(msm_mdss->reg_bus_path, 0,
		   msm_mdss->reg_bus_bw);

	ret = clk_bulk_prepare_enable(msm_mdss->num_clocks, msm_mdss->clocks);
	if (ret) {
		dev_err(msm_mdss->dev, "clock enable failed, ret:%d\n", ret);
		return ret;
	}

	/*
	 * Register access requires MDSS_MDP_CLK, which is not enabled by the
	 * mdss on mdp5 hardware. Skip it for now.
	 */
	if (msm_mdss->is_mdp5 || !msm_mdss->mdss_data)
		return 0;

	/*
	 * ubwc config is part of the "mdss" region which is not accessible
	 * from the rest of the driver. hardcode known configurations here
	 *
	 * Decoder version can be read from the UBWC_DEC_HW_VERSION reg,
	 * UBWC_n and the rest of params comes from hw data.
	 */
	switch (msm_mdss->mdss_data->ubwc_dec_version) {
	case 0: /* no UBWC */
	case UBWC_1_0:
		/* do nothing */
		break;
	case UBWC_2_0:
		msm_mdss_setup_ubwc_dec_20(msm_mdss);
		break;
	case UBWC_3_0:
		msm_mdss_setup_ubwc_dec_30(msm_mdss);
		break;
	case UBWC_4_0:
	case UBWC_4_3:
		msm_mdss_setup_ubwc_dec_40(msm_mdss);
		break;
	case UBWC_5_0:
		msm_mdss_setup_ubwc_dec_50(msm_mdss);
		break;
	default:
		dev_err(msm_mdss->dev, "Unsupported UBWC decoder version %x\n",
			msm_mdss->mdss_data->ubwc_dec_version);
		dev_err(msm_mdss->dev, "HW_REV: 0x%x\n",
			readl_relaxed(msm_mdss->mmio + REG_MDSS_HW_VERSION));
		dev_err(msm_mdss->dev, "UBWC_DEC_HW_VERSION: 0x%x\n",
			readl_relaxed(msm_mdss->mmio + REG_MDSS_UBWC_DEC_HW_VERSION));
		break;
	}

	return ret;
}

static int msm_mdss_disable(struct msm_mdss *msm_mdss)
{
	int i;

	clk_bulk_disable_unprepare(msm_mdss->num_clocks, msm_mdss->clocks);

	for (i = 0; i < msm_mdss->num_mdp_paths; i++)
		icc_set_bw(msm_mdss->mdp_path[i], 0, 0);

	if (msm_mdss->reg_bus_path)
		icc_set_bw(msm_mdss->reg_bus_path, 0, 0);

	return 0;
}

static void msm_mdss_destroy(struct msm_mdss *msm_mdss)
{
	struct platform_device *pdev = to_platform_device(msm_mdss->dev);
	int irq;

	pm_runtime_suspend(msm_mdss->dev);
	pm_runtime_disable(msm_mdss->dev);
	irq_domain_remove(msm_mdss->irq_controller.domain);
	msm_mdss->irq_controller.domain = NULL;
	irq = platform_get_irq(pdev, 0);
	irq_set_chained_handler_and_data(irq, NULL, NULL);
}

static int msm_mdss_reset(struct device *dev)
{
	struct reset_control *reset;

	reset = reset_control_get_optional_exclusive(dev, NULL);
	if (!reset) {
		/* Optional reset not specified */
		return 0;
	} else if (IS_ERR(reset)) {
		return dev_err_probe(dev, PTR_ERR(reset),
				     "failed to acquire mdss reset\n");
	}

	reset_control_assert(reset);
	/*
	 * Tests indicate that reset has to be held for some period of time,
	 * make it one frame in a typical system
	 */
	msleep(20);
	reset_control_deassert(reset);

	reset_control_put(reset);

	return 0;
}

/*
 * MDP5 MDSS uses at most three specified clocks.
 */
#define MDP5_MDSS_NUM_CLOCKS 3
static int mdp5_mdss_parse_clock(struct platform_device *pdev, struct clk_bulk_data **clocks)
{
	struct clk_bulk_data *bulk;
	int num_clocks = 0;
	int ret;

	if (!pdev)
		return -EINVAL;

	bulk = devm_kcalloc(&pdev->dev, MDP5_MDSS_NUM_CLOCKS, sizeof(struct clk_bulk_data), GFP_KERNEL);
	if (!bulk)
		return -ENOMEM;

	bulk[num_clocks++].id = "iface";
	bulk[num_clocks++].id = "bus";
	bulk[num_clocks++].id = "vsync";

	ret = devm_clk_bulk_get_optional(&pdev->dev, num_clocks, bulk);
	if (ret)
		return ret;

	*clocks = bulk;

	return num_clocks;
}

static struct msm_mdss *msm_mdss_init(struct platform_device *pdev, bool is_mdp5)
{
	const struct msm_mdss_data *mdss_data;
	struct msm_mdss *msm_mdss;
	int ret;
	int irq;

	ret = msm_mdss_reset(&pdev->dev);
	if (ret)
		return ERR_PTR(ret);

	msm_mdss = devm_kzalloc(&pdev->dev, sizeof(*msm_mdss), GFP_KERNEL);
	if (!msm_mdss)
		return ERR_PTR(-ENOMEM);

	msm_mdss->mdss_data = qcom_ubwc_config_get_data();
	if (IS_ERR(msm_mdss->mdss_data))
		return ERR_CAST(msm_mdss->mdss_data);

	mdss_data = of_device_get_match_data(&pdev->dev);
	if (!mdss_data)
		return ERR_PTR(-EINVAL);

	msm_mdss->reg_bus_bw = mdss_data->reg_bus_bw;

	msm_mdss->mmio = devm_platform_ioremap_resource_byname(pdev, is_mdp5 ? "mdss_phys" : "mdss");
	if (IS_ERR(msm_mdss->mmio))
		return ERR_CAST(msm_mdss->mmio);

	dev_dbg(&pdev->dev, "mapped mdss address space @%pK\n", msm_mdss->mmio);

	ret = msm_mdss_parse_data_bus_icc_path(&pdev->dev, msm_mdss);
	if (ret)
		return ERR_PTR(ret);

	if (is_mdp5)
		ret = mdp5_mdss_parse_clock(pdev, &msm_mdss->clocks);
	else
		ret = devm_clk_bulk_get_all(&pdev->dev, &msm_mdss->clocks);
	if (ret < 0) {
		dev_err(&pdev->dev, "failed to parse clocks, ret=%d\n", ret);
		return ERR_PTR(ret);
	}
	msm_mdss->num_clocks = ret;
	msm_mdss->is_mdp5 = is_mdp5;

	msm_mdss->dev = &pdev->dev;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return ERR_PTR(irq);

	ret = _msm_mdss_irq_domain_add(msm_mdss);
	if (ret)
		return ERR_PTR(ret);

	irq_set_chained_handler_and_data(irq, msm_mdss_irq,
					 msm_mdss);

	pm_runtime_enable(&pdev->dev);

	return msm_mdss;
}

static int __maybe_unused mdss_runtime_suspend(struct device *dev)
{
	struct msm_mdss *mdss = dev_get_drvdata(dev);

	DBG("");

	return msm_mdss_disable(mdss);
}

static int __maybe_unused mdss_runtime_resume(struct device *dev)
{
	struct msm_mdss *mdss = dev_get_drvdata(dev);

	DBG("");

	return msm_mdss_enable(mdss);
}

static int __maybe_unused mdss_pm_suspend(struct device *dev)
{

	if (pm_runtime_suspended(dev))
		return 0;

	return mdss_runtime_suspend(dev);
}

static int __maybe_unused mdss_pm_resume(struct device *dev)
{
	if (pm_runtime_suspended(dev))
		return 0;

	return mdss_runtime_resume(dev);
}

static const struct dev_pm_ops mdss_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(mdss_pm_suspend, mdss_pm_resume)
	SET_RUNTIME_PM_OPS(mdss_runtime_suspend, mdss_runtime_resume, NULL)
};

static int mdss_probe(struct platform_device *pdev)
{
	struct msm_mdss *mdss;
	bool is_mdp5 = of_device_is_compatible(pdev->dev.of_node, "qcom,mdss");
	struct device *dev = &pdev->dev;
	int ret;

	mdss = msm_mdss_init(pdev, is_mdp5);
	if (IS_ERR(mdss))
		return PTR_ERR(mdss);

	platform_set_drvdata(pdev, mdss);

	/*
	 * MDP5/DPU based devices don't have a flat hierarchy. There is a top
	 * level parent: MDSS, and children: MDP5/DPU, DSI, HDMI, eDP etc.
	 * Populate the children devices, find the MDP5/DPU node, and then add
	 * the interfaces to our components list.
	 */
	ret = of_platform_populate(dev->of_node, NULL, NULL, dev);
	if (ret) {
		DRM_DEV_ERROR(dev, "failed to populate children devices\n");
		msm_mdss_destroy(mdss);
		return ret;
	}

	return 0;
}

static void mdss_remove(struct platform_device *pdev)
{
	struct msm_mdss *mdss = platform_get_drvdata(pdev);

	of_platform_depopulate(&pdev->dev);

	msm_mdss_destroy(mdss);
}

static const struct msm_mdss_data data_57k = {
	.reg_bus_bw = 57000,
};

static const struct msm_mdss_data data_74k = {
	.reg_bus_bw = 74000,
};

static const struct msm_mdss_data data_76k8 = {
	.reg_bus_bw = 76800,
};

static const struct msm_mdss_data data_153k6 = {
	.reg_bus_bw = 153600,
};

static const struct of_device_id mdss_dt_match[] = {
	{ .compatible = "qcom,mdss", .data = &data_153k6 },
	{ .compatible = "qcom,msm8998-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,qcm2290-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sa8775p-mdss", .data = &data_74k },
	{ .compatible = "qcom,sar2130p-mdss", .data = &data_74k },
	{ .compatible = "qcom,sdm670-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sdm845-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sc7180-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sc7280-mdss", .data = &data_74k },
	{ .compatible = "qcom,sc8180x-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sc8280xp-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm6115-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm6125-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm6150-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm6350-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm6375-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm7150-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm8150-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm8250-mdss", .data = &data_76k8 },
	{ .compatible = "qcom,sm8350-mdss", .data = &data_74k },
	{ .compatible = "qcom,sm8450-mdss", .data = &data_74k },
	{ .compatible = "qcom,sm8550-mdss", .data = &data_57k },
	{ .compatible = "qcom,sm8650-mdss", .data = &data_57k },
	{ .compatible = "qcom,sm8750-mdss", .data = &data_57k },
	/* TODO: x1e8: Add reg_bus_bw with real value */
	{ .compatible = "qcom,x1e80100-mdss", .data = &data_153k6 },
	{}
};
MODULE_DEVICE_TABLE(of, mdss_dt_match);

static struct platform_driver mdss_platform_driver = {
	.probe      = mdss_probe,
	.remove     = mdss_remove,
	.driver     = {
		.name   = "msm-mdss",
		.of_match_table = mdss_dt_match,
		.pm     = &mdss_pm_ops,
	},
};

void __init msm_mdss_register(void)
{
	platform_driver_register(&mdss_platform_driver);
}

void __exit msm_mdss_unregister(void)
{
	platform_driver_unregister(&mdss_platform_driver);
}
