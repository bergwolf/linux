/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Functions to access TPS65215/TPS65219 Power Management Integrated Chips
 *
 * Copyright (C) 2022 BayLibre Incorporated - https://www.baylibre.com/
 * Copyright (C) 2024 Texas Instruments Incorporated - https://www.ti.com/
 */

#ifndef MFD_TPS65219_H
#define MFD_TPS65219_H

#include <linux/bitops.h>
#include <linux/regmap.h>
#include <linux/regulator/driver.h>

/* Chip id list*/
enum pmic_id {
	TPS65214,
	TPS65215,
	TPS65219,
};

/* I2C ID for TPS65219 part */
#define TPS65219_I2C_ID					0x24

/* All register addresses */
#define TPS65219_REG_TI_DEV_ID				0x00
#define TPS65219_REG_NVM_ID				0x01
#define TPS65219_REG_ENABLE_CTRL			0x02
#define TPS65219_REG_BUCKS_CONFIG			0x03
#define TPS65214_REG_LOCK				0x03
#define TPS65219_REG_LDO4_VOUT				0x04
#define TPS65214_REG_LDO1_VOUT_STBY			0x04
#define TPS65219_REG_LDO3_VOUT				0x05
#define TPS65215_REG_LDO2_VOUT                          0x05
#define TPS65214_REG_LDO1_VOUT				0x05
#define TPS65219_REG_LDO2_VOUT				0x06
#define TPS65214_REG_LDO2_VOUT				0x06
#define TPS65219_REG_LDO1_VOUT				0x07
#define TPS65214_REG_LDO2_VOUT_STBY			0x07
#define TPS65219_REG_BUCK3_VOUT				0x8
#define TPS65219_REG_BUCK2_VOUT				0x9
#define TPS65219_REG_BUCK1_VOUT				0xA
#define TPS65219_REG_LDO4_SEQUENCE_SLOT			0xB
#define TPS65219_REG_LDO3_SEQUENCE_SLOT			0xC
#define TPS65215_REG_LDO2_SEQUENCE_SLOT                 0xC
#define TPS65214_REG_LDO1_SEQUENCE_SLOT			0xC
#define TPS65219_REG_LDO2_SEQUENCE_SLOT			0xD
#define TPS65219_REG_LDO1_SEQUENCE_SLOT			0xE
#define TPS65219_REG_BUCK3_SEQUENCE_SLOT		0xF
#define TPS65219_REG_BUCK2_SEQUENCE_SLOT		0x10
#define TPS65219_REG_BUCK1_SEQUENCE_SLOT		0x11
#define TPS65219_REG_nRST_SEQUENCE_SLOT			0x12
#define TPS65219_REG_GPIO_SEQUENCE_SLOT			0x13
#define TPS65219_REG_GPO2_SEQUENCE_SLOT			0x14
#define TPS65214_REG_GPIO_GPI_SEQUENCE_SLOT		0x14
#define TPS65219_REG_GPO1_SEQUENCE_SLOT			0x15
#define TPS65214_REG_GPO_SEQUENCE_SLOT			0x15
#define TPS65219_REG_POWER_UP_SLOT_DURATION_1		0x16
#define TPS65219_REG_POWER_UP_SLOT_DURATION_2		0x17
/* _SLOT_DURATION_3 doesn't apply to TPS65215*/
#define TPS65219_REG_POWER_UP_SLOT_DURATION_3		0x18
#define TPS65219_REG_POWER_UP_SLOT_DURATION_4		0x19
#define TPS65214_REG_BUCK3_VOUT_STBY				0x19
#define TPS65219_REG_POWER_DOWN_SLOT_DURATION_1		0x1A
#define TPS65219_REG_POWER_DOWN_SLOT_DURATION_2		0x1B
#define TPS65219_REG_POWER_DOWN_SLOT_DURATION_3		0x1C
#define TPS65214_REG_BUCK2_VOUT_STBY				0x1C
#define TPS65219_REG_POWER_DOWN_SLOT_DURATION_4		0x1D
#define TPS65214_REG_BUCK1_VOUT_STBY				0x1D
#define TPS65219_REG_GENERAL_CONFIG			0x1E
#define TPS65219_REG_MFP_1_CONFIG			0x1F
#define TPS65219_REG_MFP_2_CONFIG			0x20
#define TPS65219_REG_STBY_1_CONFIG			0x21
#define TPS65219_REG_STBY_2_CONFIG			0x22
#define TPS65219_REG_OC_DEGL_CONFIG			0x23
/* 'sub irq' MASK registers */
#define TPS65219_REG_INT_MASK_UV			0x24
#define TPS65219_REG_MASK_CONFIG			0x25

#define TPS65219_REG_I2C_ADDRESS_REG			0x26
#define TPS65219_REG_USER_GENERAL_NVM_STORAGE		0x27
#define TPS65219_REG_MANUFACTURING_VER			0x28
#define TPS65219_REG_MFP_CTRL				0x29
#define TPS65219_REG_DISCHARGE_CONFIG			0x2A
/* main irq registers */
#define TPS65219_REG_INT_SOURCE				0x2B

/* TPS65219 'sub irq' registers */
#define TPS65219_REG_INT_LDO_3_4			0x2C
#define TPS65219_REG_INT_LDO_1_2			0x2D

/* TPS65215 specific 'sub irq' registers */
#define TPS65215_REG_INT_LDO_2				0x2C
#define TPS65215_REG_INT_LDO_1				0x2D

/* TPS65214 specific 'sub irq' register */
#define TPS65214_REG_INT_LDO_1_2			0x2D

/* Common TPS65215 & TPS65219 'sub irq' registers */
#define TPS65219_REG_INT_BUCK_3				0x2E
#define TPS65219_REG_INT_BUCK_1_2			0x2F
#define TPS65219_REG_INT_SYSTEM				0x30
#define TPS65219_REG_INT_RV				0x31
#define TPS65219_REG_INT_TIMEOUT_RV_SD			0x32
#define TPS65219_REG_INT_PB				0x33

#define TPS65219_REG_INT_LDO_3_4_POS			0
#define TPS65219_REG_INT_LDO_1_2_POS			1
#define TPS65219_REG_INT_BUCK_3_POS			2
#define TPS65219_REG_INT_BUCK_1_2_POS			3
#define TPS65219_REG_INT_SYS_POS			4
#define TPS65219_REG_INT_RV_POS				5
#define TPS65219_REG_INT_TO_RV_POS			6
#define TPS65219_REG_INT_PB_POS				7

#define TPS65215_REG_INT_LDO_2_POS			0
#define TPS65215_REG_INT_LDO_1_POS			1

#define TPS65214_REG_INT_LDO_1_2_POS		0
#define TPS65214_REG_INT_BUCK_3_POS			1
#define TPS65214_REG_INT_BUCK_1_2_POS			2
#define TPS65214_REG_INT_SYS_POS			3
#define TPS65214_REG_INT_RV_POS				4
#define TPS65214_REG_INT_TO_RV_POS			5
#define TPS65214_REG_INT_PB_POS				6

#define TPS65219_REG_USER_NVM_CMD			0x34
#define TPS65219_REG_POWER_UP_STATUS			0x35
#define TPS65219_REG_SPARE_2				0x36
#define TPS65219_REG_SPARE_3				0x37
#define TPS65219_REG_FACTORY_CONFIG_2			0x41

/* Register field definitions */
#define TPS65219_DEVID_REV_MASK				GENMASK(7, 0)
#define TPS65219_BUCKS_LDOS_VOUT_VSET_MASK		GENMASK(5, 0)
#define TPS65219_BUCKS_UV_THR_SEL_MASK			BIT(6)
#define TPS65219_BUCKS_BW_SEL_MASK			BIT(7)
#define LDO_BYP_SHIFT					6
#define TPS65219_LDOS_BYP_CONFIG_MASK			BIT(LDO_BYP_SHIFT)
#define TPS65219_LDOS_LSW_CONFIG_MASK			BIT(7)
/* Regulators enable control */
#define TPS65219_ENABLE_BUCK1_EN_MASK			BIT(0)
#define TPS65219_ENABLE_BUCK2_EN_MASK			BIT(1)
#define TPS65219_ENABLE_BUCK3_EN_MASK			BIT(2)
#define TPS65219_ENABLE_LDO1_EN_MASK			BIT(3)
#define TPS65219_ENABLE_LDO2_EN_MASK			BIT(4)
#define TPS65219_ENABLE_LDO3_EN_MASK			BIT(5)
#define TPS65215_ENABLE_LDO2_EN_MASK                    BIT(5)
#define TPS65214_ENABLE_LDO1_EN_MASK			BIT(5)
#define TPS65219_ENABLE_LDO4_EN_MASK			BIT(6)
/* power ON-OFF sequence slot */
#define TPS65219_BUCKS_LDOS_SEQUENCE_OFF_SLOT_MASK	GENMASK(3, 0)
#define TPS65219_BUCKS_LDOS_SEQUENCE_ON_SLOT_MASK	GENMASK(7, 4)
/* TODO: Not needed, same mapping as TPS65219_ENABLE_REGNAME_EN, factorize */
#define TPS65219_STBY1_BUCK1_STBY_EN_MASK		BIT(0)
#define TPS65219_STBY1_BUCK2_STBY_EN_MASK		BIT(1)
#define TPS65219_STBY1_BUCK3_STBY_EN_MASK		BIT(2)
#define TPS65219_STBY1_LDO1_STBY_EN_MASK		BIT(3)
#define TPS65219_STBY1_LDO2_STBY_EN_MASK		BIT(4)
#define TPS65219_STBY1_LDO3_STBY_EN_MASK		BIT(5)
#define TPS65219_STBY1_LDO4_STBY_EN_MASK		BIT(6)
/* STBY_2 config */
#define TPS65219_STBY2_GPO1_STBY_EN_MASK		BIT(0)
#define TPS65219_STBY2_GPO2_STBY_EN_MASK		BIT(1)
#define TPS65219_STBY2_GPIO_STBY_EN_MASK		BIT(2)
/* MFP Control */
#define TPS65219_MFP_I2C_OFF_REQ_MASK			BIT(0)
#define TPS65219_MFP_STBY_I2C_CTRL_MASK			BIT(1)
#define TPS65219_MFP_COLD_RESET_I2C_CTRL_MASK		BIT(2)
#define TPS65219_MFP_WARM_RESET_I2C_CTRL_MASK		BIT(3)
#define TPS65219_MFP_GPIO_STATUS_MASK			BIT(4)
/* MFP_1 Config */
#define TPS65219_MFP_1_VSEL_DDR_SEL_MASK		BIT(0)
#define TPS65219_MFP_1_VSEL_SD_POL_MASK			BIT(1)
#define TPS65219_MFP_1_VSEL_RAIL_MASK			BIT(2)
/* MFP_2 Config */
#define TPS65219_MFP_2_MODE_STBY_MASK			GENMASK(1, 0)
#define TPS65219_MFP_2_MODE_RESET_MASK			BIT(2)
#define TPS65219_MFP_2_EN_PB_VSENSE_DEGL_MASK		BIT(3)
#define TPS65219_MFP_2_EN_PB_VSENSE_MASK		GENMASK(5, 4)
#define TPS65219_MFP_2_WARM_COLD_RESET_MASK		BIT(6)
#define TPS65219_MFP_2_PU_ON_FSD_MASK			BIT(7)
#define TPS65219_MFP_2_EN				0
#define TPS65219_MFP_2_PB				BIT(4)
#define TPS65219_MFP_2_VSENSE				BIT(5)
/* MASK_UV Config */
#define TPS65219_REG_MASK_UV_LDO1_UV_MASK		BIT(0)
#define TPS65219_REG_MASK_UV_LDO2_UV_MASK		BIT(1)
#define TPS65219_REG_MASK_UV_LDO3_UV_MASK		BIT(2)
#define TPS65219_REG_MASK_UV_LDO4_UV_MASK		BIT(3)
#define TPS65219_REG_MASK_UV_BUCK1_UV_MASK		BIT(4)
#define TPS65219_REG_MASK_UV_BUCK2_UV_MASK		BIT(5)
#define TPS65219_REG_MASK_UV_BUCK3_UV_MASK		BIT(6)
#define TPS65219_REG_MASK_UV_RETRY_MASK			BIT(7)
/* MASK Config */
// SENSOR_N_WARM_MASK already defined in Thermal
#define TPS65219_REG_MASK_INT_FOR_RV_MASK		BIT(4)
#define TPS65219_REG_MASK_EFFECT_MASK			GENMASK(2, 1)
#define TPS65219_REG_MASK_INT_FOR_PB_MASK		BIT(7)
/* UnderVoltage - Short to GND - OverCurrent*/
/* LDO3-4: only for TPS65219*/
#define TPS65219_INT_LDO3_SCG_MASK			BIT(0)
#define TPS65219_INT_LDO3_OC_MASK			BIT(1)
#define TPS65219_INT_LDO3_UV_MASK			BIT(2)
#define TPS65219_INT_LDO4_SCG_MASK			BIT(3)
#define TPS65219_INT_LDO4_OC_MASK			BIT(4)
#define TPS65219_INT_LDO4_UV_MASK			BIT(5)
/* LDO1-2: TPS65214 & TPS65219 */
#define TPS65219_INT_LDO1_SCG_MASK			BIT(0)
#define TPS65219_INT_LDO1_OC_MASK			BIT(1)
#define TPS65219_INT_LDO1_UV_MASK			BIT(2)
#define TPS65219_INT_LDO2_SCG_MASK			BIT(3)
#define TPS65219_INT_LDO2_OC_MASK			BIT(4)
#define TPS65219_INT_LDO2_UV_MASK			BIT(5)
/* TPS65215 LDO1-2*/
#define TPS65215_INT_LDO1_SCG_MASK			BIT(0)
#define TPS65215_INT_LDO1_OC_MASK			BIT(1)
#define TPS65215_INT_LDO1_UV_MASK			BIT(2)
#define TPS65215_INT_LDO2_SCG_MASK			BIT(0)
#define TPS65215_INT_LDO2_OC_MASK			BIT(1)
#define TPS65215_INT_LDO2_UV_MASK			BIT(2)
/* BUCK3 */
#define TPS65219_INT_BUCK3_SCG_MASK			BIT(0)
#define TPS65219_INT_BUCK3_OC_MASK			BIT(1)
#define TPS65219_INT_BUCK3_NEG_OC_MASK			BIT(2)
#define TPS65219_INT_BUCK3_UV_MASK			BIT(3)
/* BUCK1-2 */
#define TPS65219_INT_BUCK1_SCG_MASK			BIT(0)
#define TPS65219_INT_BUCK1_OC_MASK			BIT(1)
#define TPS65219_INT_BUCK1_NEG_OC_MASK			BIT(2)
#define TPS65219_INT_BUCK1_UV_MASK			BIT(3)
#define TPS65219_INT_BUCK2_SCG_MASK			BIT(4)
#define TPS65219_INT_BUCK2_OC_MASK			BIT(5)
#define TPS65219_INT_BUCK2_NEG_OC_MASK			BIT(6)
#define TPS65219_INT_BUCK2_UV_MASK			BIT(7)
/* Thermal Sensor: TPS65219/TPS65215 */
#define TPS65219_INT_SENSOR_3_WARM_MASK			BIT(0)
#define TPS65219_INT_SENSOR_3_HOT_MASK			BIT(4)
/* Thermal Sensor: TPS65219/TPS65215/TPS65214 */
#define TPS65219_INT_SENSOR_2_WARM_MASK			BIT(1)
#define TPS65219_INT_SENSOR_1_WARM_MASK			BIT(2)
#define TPS65219_INT_SENSOR_0_WARM_MASK			BIT(3)
#define TPS65219_INT_SENSOR_2_HOT_MASK			BIT(5)
#define TPS65219_INT_SENSOR_1_HOT_MASK			BIT(6)
#define TPS65219_INT_SENSOR_0_HOT_MASK			BIT(7)
/* Residual Voltage */
#define TPS65219_INT_BUCK1_RV_MASK			BIT(0)
#define TPS65219_INT_BUCK2_RV_MASK			BIT(1)
#define TPS65219_INT_BUCK3_RV_MASK			BIT(2)
#define TPS65219_INT_LDO1_RV_MASK			BIT(3)
#define TPS65219_INT_LDO2_RV_MASK			BIT(4)
#define TPS65219_INT_LDO3_RV_MASK			BIT(5)
#define TPS65215_INT_LDO2_RV_MASK			BIT(5)
#define TPS65214_INT_LDO2_RV_MASK			BIT(5)
#define TPS65219_INT_LDO4_RV_MASK			BIT(6)
/* Residual Voltage ShutDown */
#define TPS65219_INT_BUCK1_RV_SD_MASK			BIT(0)
#define TPS65219_INT_BUCK2_RV_SD_MASK			BIT(1)
#define TPS65219_INT_BUCK3_RV_SD_MASK			BIT(2)
#define TPS65219_INT_LDO1_RV_SD_MASK			BIT(3)
#define TPS65219_INT_LDO2_RV_SD_MASK			BIT(4)
#define TPS65219_INT_LDO3_RV_SD_MASK			BIT(5)
#define TPS65215_INT_LDO2_RV_SD_MASK			BIT(5)
#define TPS65214_INT_LDO1_RV_SD_MASK			BIT(5)
#define TPS65219_INT_LDO4_RV_SD_MASK			BIT(6)
#define TPS65219_INT_TIMEOUT_MASK			BIT(7)
/* Power Button */
#define TPS65219_INT_PB_FALLING_EDGE_DETECT_MASK	BIT(0)
#define TPS65219_INT_PB_RISING_EDGE_DETECT_MASK		BIT(1)
#define TPS65219_INT_PB_REAL_TIME_STATUS_MASK		BIT(2)

#define TPS65219_PB_POS					7
#define TPS65219_TO_RV_POS				6
#define TPS65219_RV_POS					5
#define TPS65219_SYS_POS				4
#define TPS65219_BUCK_1_2_POS				3
#define TPS65219_BUCK_3_POS				2
#define TPS65219_LDO_1_2_POS				1
#define TPS65219_LDO_3_4_POS				0

/* IRQs */
enum {
	/* LDO3-4 register IRQs */
	TPS65219_INT_LDO3_SCG,
	TPS65219_INT_LDO3_OC,
	TPS65219_INT_LDO3_UV,
	TPS65219_INT_LDO4_SCG,
	TPS65219_INT_LDO4_OC,
	TPS65219_INT_LDO4_UV,
	/* TPS65215 LDO1*/
	TPS65215_INT_LDO1_SCG,
	TPS65215_INT_LDO1_OC,
	TPS65215_INT_LDO1_UV,
	/* TPS65215 LDO2*/
	TPS65215_INT_LDO2_SCG,
	TPS65215_INT_LDO2_OC,
	TPS65215_INT_LDO2_UV,
	/* LDO1-2: TPS65219/TPS65214 */
	TPS65219_INT_LDO1_SCG,
	TPS65219_INT_LDO1_OC,
	TPS65219_INT_LDO1_UV,
	TPS65219_INT_LDO2_SCG,
	TPS65219_INT_LDO2_OC,
	TPS65219_INT_LDO2_UV,
	/* BUCK3 */
	TPS65219_INT_BUCK3_SCG,
	TPS65219_INT_BUCK3_OC,
	TPS65219_INT_BUCK3_NEG_OC,
	TPS65219_INT_BUCK3_UV,
	/* BUCK1-2 */
	TPS65219_INT_BUCK1_SCG,
	TPS65219_INT_BUCK1_OC,
	TPS65219_INT_BUCK1_NEG_OC,
	TPS65219_INT_BUCK1_UV,
	TPS65219_INT_BUCK2_SCG,
	TPS65219_INT_BUCK2_OC,
	TPS65219_INT_BUCK2_NEG_OC,
	TPS65219_INT_BUCK2_UV,
	/* Thermal Sensor  */
	TPS65219_INT_SENSOR_3_WARM,
	TPS65219_INT_SENSOR_2_WARM,
	TPS65219_INT_SENSOR_1_WARM,
	TPS65219_INT_SENSOR_0_WARM,
	TPS65219_INT_SENSOR_3_HOT,
	TPS65219_INT_SENSOR_2_HOT,
	TPS65219_INT_SENSOR_1_HOT,
	TPS65219_INT_SENSOR_0_HOT,
	/* Residual Voltage */
	TPS65219_INT_BUCK1_RV,
	TPS65219_INT_BUCK2_RV,
	TPS65219_INT_BUCK3_RV,
	TPS65219_INT_LDO1_RV,
	TPS65219_INT_LDO2_RV,
	TPS65215_INT_LDO2_RV,
	TPS65214_INT_LDO2_RV,
	TPS65219_INT_LDO3_RV,
	TPS65219_INT_LDO4_RV,
	/* Residual Voltage ShutDown */
	TPS65219_INT_BUCK1_RV_SD,
	TPS65219_INT_BUCK2_RV_SD,
	TPS65219_INT_BUCK3_RV_SD,
	TPS65219_INT_LDO1_RV_SD,
	TPS65214_INT_LDO1_RV_SD,
	TPS65215_INT_LDO2_RV_SD,
	TPS65219_INT_LDO2_RV_SD,
	TPS65219_INT_LDO3_RV_SD,
	TPS65219_INT_LDO4_RV_SD,
	TPS65219_INT_TIMEOUT,
	/* Power Button */
	TPS65219_INT_PB_FALLING_EDGE_DETECT,
	TPS65219_INT_PB_RISING_EDGE_DETECT,
};

enum tps65214_regulator_id {
	/*
	 * DCDC's same as TPS65219
	 * LDO1 maps to TPS65219's LDO3
	 * LDO2 is the same as TPS65219
	 *
	 */
	TPS65214_LDO_1 = 3,
	TPS65214_LDO_2 = 4,
};

enum tps65215_regulator_id {
	/* DCDC's same as TPS65219 */
	/* LDO1 is the same as TPS65219 */
	TPS65215_LDO_2 = 4,
};

enum tps65219_regulator_id {
	/* DCDC's */
	TPS65219_BUCK_1,
	TPS65219_BUCK_2,
	TPS65219_BUCK_3,
	/* LDOs */
	TPS65219_LDO_1,
	TPS65219_LDO_2,
	TPS65219_LDO_3,
	TPS65219_LDO_4,
};

/* Number of step-down converters available */
#define TPS6521X_NUM_BUCKS		3
/* Number of LDO voltage regulators available */
#define TPS65219_NUM_LDO		4
#define TPS65215_NUM_LDO		2
#define TPS65214_NUM_LDO		2
/* Number of total regulators available */
#define TPS65219_NUM_REGULATOR		(TPS6521X_NUM_BUCKS + TPS65219_NUM_LDO)
#define TPS65215_NUM_REGULATOR		(TPS6521X_NUM_BUCKS + TPS65215_NUM_LDO)
#define TPS65214_NUM_REGULATOR		(TPS6521X_NUM_BUCKS + TPS65214_NUM_LDO)

/* Define the TPS65214 IRQ numbers */
enum tps65214_irqs {
	/* INT source registers */
	TPS65214_TO_RV_SD_SET_IRQ,
	TPS65214_RV_SET_IRQ,
	TPS65214_SYS_SET_IRQ,
	TPS65214_BUCK_1_2_SET_IRQ,
	TPS65214_BUCK_3_SET_IRQ,
	TPS65214_LDO_1_2_SET_IRQ,
	TPS65214_PB_SET_IRQ = 7,
};

/* Define the TPS65215 IRQ numbers */
enum tps65215_irqs {
	/* INT source registers */
	TPS65215_TO_RV_SD_SET_IRQ,
	TPS65215_RV_SET_IRQ,
	TPS65215_SYS_SET_IRQ,
	TPS65215_BUCK_1_2_SET_IRQ,
	TPS65215_BUCK_3_SET_IRQ,
	TPS65215_LDO_1_SET_IRQ,
	TPS65215_LDO_2_SET_IRQ,
	TPS65215_PB_SET_IRQ,
};

/* Define the TPS65219 IRQ numbers */
enum tps65219_irqs {
	/* INT source registers */
	TPS65219_TO_RV_SD_SET_IRQ,
	TPS65219_RV_SET_IRQ,
	TPS65219_SYS_SET_IRQ,
	TPS65219_BUCK_1_2_SET_IRQ,
	TPS65219_BUCK_3_SET_IRQ,
	TPS65219_LDO_1_2_SET_IRQ,
	TPS65219_LDO_3_4_SET_IRQ,
	TPS65219_PB_SET_IRQ,
};

/**
 * struct tps65219 - tps65219 sub-driver chip access routines
 *
 * Device data may be used to access the TPS65219 chip
 *
 * @dev: MFD device
 * @regmap: Regmap for accessing the device registers
 * @irq_data: Regmap irq data used for the irq chip
 */
struct tps65219 {
	struct device *dev;
	struct regmap *regmap;

	struct regmap_irq_chip_data *irq_data;
};

#endif /* MFD_TPS65219_H */
