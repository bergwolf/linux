/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Universal Flash Storage Host controller driver
 * Copyright (C) 2011-2013 Samsung India Software Operations
 *
 * Authors:
 *	Santosh Yaraganavi <santosh.sy@samsung.com>
 *	Vinayak Holikatti <h.vinayak@samsung.com>
 */

#ifndef _UFS_H
#define _UFS_H

#include <linux/bitops.h>
#include <linux/types.h>
#include <uapi/scsi/scsi_bsg_ufs.h>
#include <linux/time64.h>

/*
 * Using static_assert() is not allowed in UAPI header files. Hence the check
 * in this header file of the size of struct utp_upiu_header.
 */
static_assert(sizeof(struct utp_upiu_header) == 12);

#define GENERAL_UPIU_REQUEST_SIZE (sizeof(struct utp_upiu_req))
#define QUERY_DESC_MAX_SIZE       255
#define QUERY_DESC_MIN_SIZE       2
#define QUERY_DESC_HDR_SIZE       2
#define QUERY_OSF_SIZE            (GENERAL_UPIU_REQUEST_SIZE - \
					(sizeof(struct utp_upiu_header)))
#define UFS_SENSE_SIZE	18

/*
 * UFS device may have standard LUs and LUN id could be from 0x00 to
 * 0x7F. Standard LUs use "Peripheral Device Addressing Format".
 * UFS device may also have the Well Known LUs (also referred as W-LU)
 * which again could be from 0x00 to 0x7F. For W-LUs, device only use
 * the "Extended Addressing Format" which means the W-LUNs would be
 * from 0xc100 (SCSI_W_LUN_BASE) onwards.
 * This means max. LUN number reported from UFS device could be 0xC17F.
 */
#define UFS_UPIU_MAX_UNIT_NUM_ID	0x7F
#define UFS_MAX_LUNS		(SCSI_W_LUN_BASE + UFS_UPIU_MAX_UNIT_NUM_ID)
#define UFS_UPIU_WLUN_ID	(1 << 7)

/* WriteBooster buffer is available only for the logical unit from 0 to 7 */
#define UFS_UPIU_MAX_WB_LUN_ID	8

/*
 * WriteBooster buffer lifetime has a limit setted by vendor.
 * If it is over the limit, WriteBooster feature will be disabled.
 */
#define UFS_WB_EXCEED_LIFETIME		0x0B

/*
 * In UFS Spec, the Extra Header Segment (EHS) starts from byte 32 in UPIU request/response packet
 */
#define EHS_OFFSET_IN_RESPONSE 32

/* Well known logical unit id in LUN field of UPIU */
enum {
	UFS_UPIU_REPORT_LUNS_WLUN	= 0x81,
	UFS_UPIU_UFS_DEVICE_WLUN	= 0xD0,
	UFS_UPIU_BOOT_WLUN		= 0xB0,
	UFS_UPIU_RPMB_WLUN		= 0xC4,
};

/*
 * UFS Protocol Information Unit related definitions
 */

/* Task management functions */
enum {
	UFS_ABORT_TASK		= 0x01,
	UFS_ABORT_TASK_SET	= 0x02,
	UFS_CLEAR_TASK_SET	= 0x04,
	UFS_LOGICAL_RESET	= 0x08,
	UFS_QUERY_TASK		= 0x80,
	UFS_QUERY_TASK_SET	= 0x81,
};

/* UTP UPIU Transaction Codes Initiator to Target */
enum upiu_request_transaction {
	UPIU_TRANSACTION_NOP_OUT	= 0x00,
	UPIU_TRANSACTION_COMMAND	= 0x01,
	UPIU_TRANSACTION_DATA_OUT	= 0x02,
	UPIU_TRANSACTION_TASK_REQ	= 0x04,
	UPIU_TRANSACTION_QUERY_REQ	= 0x16,
};

/* UTP UPIU Transaction Codes Target to Initiator */
enum upiu_response_transaction {
	UPIU_TRANSACTION_NOP_IN		= 0x20,
	UPIU_TRANSACTION_RESPONSE	= 0x21,
	UPIU_TRANSACTION_DATA_IN	= 0x22,
	UPIU_TRANSACTION_TASK_RSP	= 0x24,
	UPIU_TRANSACTION_READY_XFER	= 0x31,
	UPIU_TRANSACTION_QUERY_RSP	= 0x36,
	UPIU_TRANSACTION_REJECT_UPIU	= 0x3F,
};

/* UPIU Read/Write flags. See also table "UPIU Flags" in the UFS standard. */
enum {
	UPIU_CMD_FLAGS_NONE	= 0x00,
	UPIU_CMD_FLAGS_CP	= 0x04,
	UPIU_CMD_FLAGS_WRITE	= 0x20,
	UPIU_CMD_FLAGS_READ	= 0x40,
};

/* UPIU response flags */
enum {
	UPIU_RSP_FLAG_UNDERFLOW	= 0x20,
	UPIU_RSP_FLAG_OVERFLOW	= 0x40,
};

/* UPIU Task Attributes */
enum {
	UPIU_TASK_ATTR_SIMPLE	= 0x00,
	UPIU_TASK_ATTR_ORDERED	= 0x01,
	UPIU_TASK_ATTR_HEADQ	= 0x02,
	UPIU_TASK_ATTR_ACA	= 0x03,
};

/* UPIU Query request function */
enum {
	UPIU_QUERY_FUNC_STANDARD_READ_REQUEST           = 0x01,
	UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST          = 0x81,
};

/* Flag idn for Query Requests*/
enum flag_idn {
	QUERY_FLAG_IDN_FDEVICEINIT			= 0x01,
	QUERY_FLAG_IDN_PERMANENT_WPE			= 0x02,
	QUERY_FLAG_IDN_PWR_ON_WPE			= 0x03,
	QUERY_FLAG_IDN_BKOPS_EN				= 0x04,
	QUERY_FLAG_IDN_LIFE_SPAN_MODE_ENABLE		= 0x05,
	QUERY_FLAG_IDN_PURGE_ENABLE			= 0x06,
	QUERY_FLAG_IDN_RESERVED2			= 0x07,
	QUERY_FLAG_IDN_FPHYRESOURCEREMOVAL		= 0x08,
	QUERY_FLAG_IDN_BUSY_RTC				= 0x09,
	QUERY_FLAG_IDN_RESERVED3			= 0x0A,
	QUERY_FLAG_IDN_PERMANENTLY_DISABLE_FW_UPDATE	= 0x0B,
	QUERY_FLAG_IDN_WB_EN                            = 0x0E,
	QUERY_FLAG_IDN_WB_BUFF_FLUSH_EN                 = 0x0F,
	QUERY_FLAG_IDN_WB_BUFF_FLUSH_DURING_HIBERN8     = 0x10,
	QUERY_FLAG_IDN_HPB_RESET                        = 0x11,
	QUERY_FLAG_IDN_HPB_EN				= 0x12,
};

/* Attribute idn for Query requests */
enum attr_idn {
	QUERY_ATTR_IDN_BOOT_LU_EN		= 0x00,
	QUERY_ATTR_IDN_MAX_HPB_SINGLE_CMD	= 0x01,
	QUERY_ATTR_IDN_POWER_MODE		= 0x02,
	QUERY_ATTR_IDN_ACTIVE_ICC_LVL		= 0x03,
	QUERY_ATTR_IDN_OOO_DATA_EN		= 0x04,
	QUERY_ATTR_IDN_BKOPS_STATUS		= 0x05,
	QUERY_ATTR_IDN_PURGE_STATUS		= 0x06,
	QUERY_ATTR_IDN_MAX_DATA_IN		= 0x07,
	QUERY_ATTR_IDN_MAX_DATA_OUT		= 0x08,
	QUERY_ATTR_IDN_DYN_CAP_NEEDED		= 0x09,
	QUERY_ATTR_IDN_REF_CLK_FREQ		= 0x0A,
	QUERY_ATTR_IDN_CONF_DESC_LOCK		= 0x0B,
	QUERY_ATTR_IDN_MAX_NUM_OF_RTT		= 0x0C,
	QUERY_ATTR_IDN_EE_CONTROL		= 0x0D,
	QUERY_ATTR_IDN_EE_STATUS		= 0x0E,
	QUERY_ATTR_IDN_SECONDS_PASSED		= 0x0F,
	QUERY_ATTR_IDN_CNTX_CONF		= 0x10,
	QUERY_ATTR_IDN_CORR_PRG_BLK_NUM		= 0x11,
	QUERY_ATTR_IDN_RESERVED2		= 0x12,
	QUERY_ATTR_IDN_RESERVED3		= 0x13,
	QUERY_ATTR_IDN_FFU_STATUS		= 0x14,
	QUERY_ATTR_IDN_PSA_STATE		= 0x15,
	QUERY_ATTR_IDN_PSA_DATA_SIZE		= 0x16,
	QUERY_ATTR_IDN_REF_CLK_GATING_WAIT_TIME	= 0x17,
	QUERY_ATTR_IDN_CASE_ROUGH_TEMP          = 0x18,
	QUERY_ATTR_IDN_HIGH_TEMP_BOUND          = 0x19,
	QUERY_ATTR_IDN_LOW_TEMP_BOUND           = 0x1A,
	QUERY_ATTR_IDN_WB_FLUSH_STATUS	        = 0x1C,
	QUERY_ATTR_IDN_AVAIL_WB_BUFF_SIZE       = 0x1D,
	QUERY_ATTR_IDN_WB_BUFF_LIFE_TIME_EST    = 0x1E,
	QUERY_ATTR_IDN_CURR_WB_BUFF_SIZE        = 0x1F,
	QUERY_ATTR_IDN_TIMESTAMP		= 0x30,
	QUERY_ATTR_IDN_DEV_LVL_EXCEPTION_ID     = 0x34,
	QUERY_ATTR_IDN_HID_DEFRAG_OPERATION	= 0x35,
	QUERY_ATTR_IDN_HID_AVAILABLE_SIZE	= 0x36,
	QUERY_ATTR_IDN_HID_SIZE			= 0x37,
	QUERY_ATTR_IDN_HID_PROGRESS_RATIO	= 0x38,
	QUERY_ATTR_IDN_HID_STATE		= 0x39,
	QUERY_ATTR_IDN_WB_BUF_RESIZE_HINT	= 0x3C,
	QUERY_ATTR_IDN_WB_BUF_RESIZE_EN		= 0x3D,
	QUERY_ATTR_IDN_WB_BUF_RESIZE_STATUS	= 0x3E,
};

/* Descriptor idn for Query requests */
enum desc_idn {
	QUERY_DESC_IDN_DEVICE		= 0x0,
	QUERY_DESC_IDN_CONFIGURATION	= 0x1,
	QUERY_DESC_IDN_UNIT		= 0x2,
	QUERY_DESC_IDN_RFU_0		= 0x3,
	QUERY_DESC_IDN_INTERCONNECT	= 0x4,
	QUERY_DESC_IDN_STRING		= 0x5,
	QUERY_DESC_IDN_RFU_1		= 0x6,
	QUERY_DESC_IDN_GEOMETRY		= 0x7,
	QUERY_DESC_IDN_POWER		= 0x8,
	QUERY_DESC_IDN_HEALTH           = 0x9,
	QUERY_DESC_IDN_MAX,
};

enum desc_header_offset {
	QUERY_DESC_LENGTH_OFFSET	= 0x00,
	QUERY_DESC_DESC_TYPE_OFFSET	= 0x01,
};

/* Unit descriptor parameters offsets in bytes*/
enum unit_desc_param {
	UNIT_DESC_PARAM_LEN			= 0x0,
	UNIT_DESC_PARAM_TYPE			= 0x1,
	UNIT_DESC_PARAM_UNIT_INDEX		= 0x2,
	UNIT_DESC_PARAM_LU_ENABLE		= 0x3,
	UNIT_DESC_PARAM_BOOT_LUN_ID		= 0x4,
	UNIT_DESC_PARAM_LU_WR_PROTECT		= 0x5,
	UNIT_DESC_PARAM_LU_Q_DEPTH		= 0x6,
	UNIT_DESC_PARAM_PSA_SENSITIVE		= 0x7,
	UNIT_DESC_PARAM_MEM_TYPE		= 0x8,
	UNIT_DESC_PARAM_DATA_RELIABILITY	= 0x9,
	UNIT_DESC_PARAM_LOGICAL_BLK_SIZE	= 0xA,
	UNIT_DESC_PARAM_LOGICAL_BLK_COUNT	= 0xB,
	UNIT_DESC_PARAM_ERASE_BLK_SIZE		= 0x13,
	UNIT_DESC_PARAM_PROVISIONING_TYPE	= 0x17,
	UNIT_DESC_PARAM_PHY_MEM_RSRC_CNT	= 0x18,
	UNIT_DESC_PARAM_CTX_CAPABILITIES	= 0x20,
	UNIT_DESC_PARAM_LARGE_UNIT_SIZE_M1	= 0x22,
	UNIT_DESC_PARAM_HPB_LU_MAX_ACTIVE_RGNS	= 0x23,
	UNIT_DESC_PARAM_HPB_PIN_RGN_START_OFF	= 0x25,
	UNIT_DESC_PARAM_HPB_NUM_PIN_RGNS	= 0x27,
	UNIT_DESC_PARAM_WB_BUF_ALLOC_UNITS	= 0x29,
};

/* RPMB Unit descriptor parameters offsets in bytes*/
enum rpmb_unit_desc_param {
	RPMB_UNIT_DESC_PARAM_LEN		= 0x0,
	RPMB_UNIT_DESC_PARAM_TYPE		= 0x1,
	RPMB_UNIT_DESC_PARAM_UNIT_INDEX		= 0x2,
	RPMB_UNIT_DESC_PARAM_LU_ENABLE		= 0x3,
	RPMB_UNIT_DESC_PARAM_BOOT_LUN_ID	= 0x4,
	RPMB_UNIT_DESC_PARAM_LU_WR_PROTECT	= 0x5,
	RPMB_UNIT_DESC_PARAM_LU_Q_DEPTH		= 0x6,
	RPMB_UNIT_DESC_PARAM_PSA_SENSITIVE	= 0x7,
	RPMB_UNIT_DESC_PARAM_MEM_TYPE		= 0x8,
	RPMB_UNIT_DESC_PARAM_REGION_EN		= 0x9,
	RPMB_UNIT_DESC_PARAM_LOGICAL_BLK_SIZE	= 0xA,
	RPMB_UNIT_DESC_PARAM_LOGICAL_BLK_COUNT	= 0xB,
	RPMB_UNIT_DESC_PARAM_REGION0_SIZE	= 0x13,
	RPMB_UNIT_DESC_PARAM_REGION1_SIZE	= 0x14,
	RPMB_UNIT_DESC_PARAM_REGION2_SIZE	= 0x15,
	RPMB_UNIT_DESC_PARAM_REGION3_SIZE	= 0x16,
	RPMB_UNIT_DESC_PARAM_PROVISIONING_TYPE	= 0x17,
	RPMB_UNIT_DESC_PARAM_PHY_MEM_RSRC_CNT	= 0x18,
};

/* Device descriptor parameters offsets in bytes*/
enum device_desc_param {
	DEVICE_DESC_PARAM_LEN			= 0x0,
	DEVICE_DESC_PARAM_TYPE			= 0x1,
	DEVICE_DESC_PARAM_DEVICE_TYPE		= 0x2,
	DEVICE_DESC_PARAM_DEVICE_CLASS		= 0x3,
	DEVICE_DESC_PARAM_DEVICE_SUB_CLASS	= 0x4,
	DEVICE_DESC_PARAM_PRTCL			= 0x5,
	DEVICE_DESC_PARAM_NUM_LU		= 0x6,
	DEVICE_DESC_PARAM_NUM_WLU		= 0x7,
	DEVICE_DESC_PARAM_BOOT_ENBL		= 0x8,
	DEVICE_DESC_PARAM_DESC_ACCSS_ENBL	= 0x9,
	DEVICE_DESC_PARAM_INIT_PWR_MODE		= 0xA,
	DEVICE_DESC_PARAM_HIGH_PR_LUN		= 0xB,
	DEVICE_DESC_PARAM_SEC_RMV_TYPE		= 0xC,
	DEVICE_DESC_PARAM_SEC_LU		= 0xD,
	DEVICE_DESC_PARAM_BKOP_TERM_LT		= 0xE,
	DEVICE_DESC_PARAM_ACTVE_ICC_LVL		= 0xF,
	DEVICE_DESC_PARAM_SPEC_VER		= 0x10,
	DEVICE_DESC_PARAM_MANF_DATE		= 0x12,
	DEVICE_DESC_PARAM_MANF_NAME		= 0x14,
	DEVICE_DESC_PARAM_PRDCT_NAME		= 0x15,
	DEVICE_DESC_PARAM_SN			= 0x16,
	DEVICE_DESC_PARAM_OEM_ID		= 0x17,
	DEVICE_DESC_PARAM_MANF_ID		= 0x18,
	DEVICE_DESC_PARAM_UD_OFFSET		= 0x1A,
	DEVICE_DESC_PARAM_UD_LEN		= 0x1B,
	DEVICE_DESC_PARAM_RTT_CAP		= 0x1C,
	DEVICE_DESC_PARAM_FRQ_RTC		= 0x1D,
	DEVICE_DESC_PARAM_UFS_FEAT		= 0x1F,
	DEVICE_DESC_PARAM_FFU_TMT		= 0x20,
	DEVICE_DESC_PARAM_Q_DPTH		= 0x21,
	DEVICE_DESC_PARAM_DEV_VER		= 0x22,
	DEVICE_DESC_PARAM_NUM_SEC_WPA		= 0x24,
	DEVICE_DESC_PARAM_PSA_MAX_DATA		= 0x25,
	DEVICE_DESC_PARAM_PSA_TMT		= 0x29,
	DEVICE_DESC_PARAM_PRDCT_REV		= 0x2A,
	DEVICE_DESC_PARAM_HPB_VER		= 0x40,
	DEVICE_DESC_PARAM_HPB_CONTROL		= 0x42,
	DEVICE_DESC_PARAM_EXT_WB_SUP		= 0x4D,
	DEVICE_DESC_PARAM_EXT_UFS_FEATURE_SUP	= 0x4F,
	DEVICE_DESC_PARAM_WB_PRESRV_USRSPC_EN	= 0x53,
	DEVICE_DESC_PARAM_WB_TYPE		= 0x54,
	DEVICE_DESC_PARAM_WB_SHARED_ALLOC_UNITS = 0x55,
};

/* Interconnect descriptor parameters offsets in bytes*/
enum interconnect_desc_param {
	INTERCONNECT_DESC_PARAM_LEN		= 0x0,
	INTERCONNECT_DESC_PARAM_TYPE		= 0x1,
	INTERCONNECT_DESC_PARAM_UNIPRO_VER	= 0x2,
	INTERCONNECT_DESC_PARAM_MPHY_VER	= 0x4,
};

/* Geometry descriptor parameters offsets in bytes*/
enum geometry_desc_param {
	GEOMETRY_DESC_PARAM_LEN			= 0x0,
	GEOMETRY_DESC_PARAM_TYPE		= 0x1,
	GEOMETRY_DESC_PARAM_DEV_CAP		= 0x4,
	GEOMETRY_DESC_PARAM_MAX_NUM_LUN		= 0xC,
	GEOMETRY_DESC_PARAM_SEG_SIZE		= 0xD,
	GEOMETRY_DESC_PARAM_ALLOC_UNIT_SIZE	= 0x11,
	GEOMETRY_DESC_PARAM_MIN_BLK_SIZE	= 0x12,
	GEOMETRY_DESC_PARAM_OPT_RD_BLK_SIZE	= 0x13,
	GEOMETRY_DESC_PARAM_OPT_WR_BLK_SIZE	= 0x14,
	GEOMETRY_DESC_PARAM_MAX_IN_BUF_SIZE	= 0x15,
	GEOMETRY_DESC_PARAM_MAX_OUT_BUF_SIZE	= 0x16,
	GEOMETRY_DESC_PARAM_RPMB_RW_SIZE	= 0x17,
	GEOMETRY_DESC_PARAM_DYN_CAP_RSRC_PLC	= 0x18,
	GEOMETRY_DESC_PARAM_DATA_ORDER		= 0x19,
	GEOMETRY_DESC_PARAM_MAX_NUM_CTX		= 0x1A,
	GEOMETRY_DESC_PARAM_TAG_UNIT_SIZE	= 0x1B,
	GEOMETRY_DESC_PARAM_TAG_RSRC_SIZE	= 0x1C,
	GEOMETRY_DESC_PARAM_SEC_RM_TYPES	= 0x1D,
	GEOMETRY_DESC_PARAM_MEM_TYPES		= 0x1E,
	GEOMETRY_DESC_PARAM_SCM_MAX_NUM_UNITS	= 0x20,
	GEOMETRY_DESC_PARAM_SCM_CAP_ADJ_FCTR	= 0x24,
	GEOMETRY_DESC_PARAM_NPM_MAX_NUM_UNITS	= 0x26,
	GEOMETRY_DESC_PARAM_NPM_CAP_ADJ_FCTR	= 0x2A,
	GEOMETRY_DESC_PARAM_ENM1_MAX_NUM_UNITS	= 0x2C,
	GEOMETRY_DESC_PARAM_ENM1_CAP_ADJ_FCTR	= 0x30,
	GEOMETRY_DESC_PARAM_ENM2_MAX_NUM_UNITS	= 0x32,
	GEOMETRY_DESC_PARAM_ENM2_CAP_ADJ_FCTR	= 0x36,
	GEOMETRY_DESC_PARAM_ENM3_MAX_NUM_UNITS	= 0x38,
	GEOMETRY_DESC_PARAM_ENM3_CAP_ADJ_FCTR	= 0x3C,
	GEOMETRY_DESC_PARAM_ENM4_MAX_NUM_UNITS	= 0x3E,
	GEOMETRY_DESC_PARAM_ENM4_CAP_ADJ_FCTR	= 0x42,
	GEOMETRY_DESC_PARAM_OPT_LOG_BLK_SIZE	= 0x44,
	GEOMETRY_DESC_PARAM_HPB_REGION_SIZE	= 0x48,
	GEOMETRY_DESC_PARAM_HPB_NUMBER_LU	= 0x49,
	GEOMETRY_DESC_PARAM_HPB_SUBREGION_SIZE	= 0x4A,
	GEOMETRY_DESC_PARAM_HPB_MAX_ACTIVE_REGS	= 0x4B,
	GEOMETRY_DESC_PARAM_WB_MAX_ALLOC_UNITS	= 0x4F,
	GEOMETRY_DESC_PARAM_WB_MAX_WB_LUNS	= 0x53,
	GEOMETRY_DESC_PARAM_WB_BUFF_CAP_ADJ	= 0x54,
	GEOMETRY_DESC_PARAM_WB_SUP_RED_TYPE	= 0x55,
	GEOMETRY_DESC_PARAM_WB_SUP_WB_TYPE	= 0x56,
};

/* Health descriptor parameters offsets in bytes*/
enum health_desc_param {
	HEALTH_DESC_PARAM_LEN			= 0x0,
	HEALTH_DESC_PARAM_TYPE			= 0x1,
	HEALTH_DESC_PARAM_EOL_INFO		= 0x2,
	HEALTH_DESC_PARAM_LIFE_TIME_EST_A	= 0x3,
	HEALTH_DESC_PARAM_LIFE_TIME_EST_B	= 0x4,
};

/* WriteBooster buffer mode */
enum {
	WB_BUF_MODE_LU_DEDICATED	= 0x0,
	WB_BUF_MODE_SHARED		= 0x1,
};

/*
 * Logical Unit Write Protect
 * 00h: LU not write protected
 * 01h: LU write protected when fPowerOnWPEn =1
 * 02h: LU permanently write protected when fPermanentWPEn =1
 */
enum ufs_lu_wp_type {
	UFS_LU_NO_WP		= 0x00,
	UFS_LU_POWER_ON_WP	= 0x01,
	UFS_LU_PERM_WP		= 0x02,
};

/* bActiveICCLevel parameter current units */
enum {
	UFSHCD_NANO_AMP		= 0,
	UFSHCD_MICRO_AMP	= 1,
	UFSHCD_MILI_AMP		= 2,
	UFSHCD_AMP		= 3,
};

/* Possible values for wExtendedWriteBoosterSupport */
enum {
	UFS_DEV_WB_BUF_RESIZE	= BIT(0),
};

/* Possible values for dExtendedUFSFeaturesSupport */
enum {
	UFS_DEV_HIGH_TEMP_NOTIF		= BIT(4),
	UFS_DEV_LOW_TEMP_NOTIF		= BIT(5),
	UFS_DEV_EXT_TEMP_NOTIF		= BIT(6),
	UFS_DEV_HPB_SUPPORT		= BIT(7),
	UFS_DEV_WRITE_BOOSTER_SUP	= BIT(8),
	UFS_DEV_LVL_EXCEPTION_SUP       = BIT(12),
	UFS_DEV_HID_SUPPORT		= BIT(13),
};
#define UFS_DEV_HPB_SUPPORT_VERSION		0x310

#define POWER_DESC_MAX_ACTV_ICC_LVLS		16

/* Attribute  bActiveICCLevel parameter bit masks definitions */
#define ATTR_ICC_LVL_UNIT_OFFSET	14
#define ATTR_ICC_LVL_UNIT_MASK		(0x3 << ATTR_ICC_LVL_UNIT_OFFSET)
#define ATTR_ICC_LVL_VALUE_MASK		0x3FF

/* Power descriptor parameters offsets in bytes */
enum power_desc_param_offset {
	PWR_DESC_LEN			= 0x0,
	PWR_DESC_TYPE			= 0x1,
	PWR_DESC_ACTIVE_LVLS_VCC_0	= 0x2,
	PWR_DESC_ACTIVE_LVLS_VCCQ_0	= 0x22,
	PWR_DESC_ACTIVE_LVLS_VCCQ2_0	= 0x42,
};

/* Exception event mask values */
enum {
	MASK_EE_STATUS			= 0xFFFF,
	MASK_EE_DYNCAP_EVENT		= BIT(0),
	MASK_EE_SYSPOOL_EVENT		= BIT(1),
	MASK_EE_URGENT_BKOPS		= BIT(2),
	MASK_EE_TOO_HIGH_TEMP		= BIT(3),
	MASK_EE_TOO_LOW_TEMP		= BIT(4),
	MASK_EE_WRITEBOOSTER_EVENT	= BIT(5),
	MASK_EE_PERFORMANCE_THROTTLING	= BIT(6),
	MASK_EE_DEV_LVL_EXCEPTION       = BIT(7),
	MASK_EE_HEALTH_CRITICAL		= BIT(9),
};
#define MASK_EE_URGENT_TEMP (MASK_EE_TOO_HIGH_TEMP | MASK_EE_TOO_LOW_TEMP)

/* Background operation status */
enum bkops_status {
	BKOPS_STATUS_NO_OP               = 0x0,
	BKOPS_STATUS_NON_CRITICAL        = 0x1,
	BKOPS_STATUS_PERF_IMPACT         = 0x2,
	BKOPS_STATUS_CRITICAL            = 0x3,
	BKOPS_STATUS_MAX		 = BKOPS_STATUS_CRITICAL,
};

/* UTP QUERY Transaction Specific Fields OpCode */
enum query_opcode {
	UPIU_QUERY_OPCODE_NOP		= 0x0,
	UPIU_QUERY_OPCODE_READ_DESC	= 0x1,
	UPIU_QUERY_OPCODE_WRITE_DESC	= 0x2,
	UPIU_QUERY_OPCODE_READ_ATTR	= 0x3,
	UPIU_QUERY_OPCODE_WRITE_ATTR	= 0x4,
	UPIU_QUERY_OPCODE_READ_FLAG	= 0x5,
	UPIU_QUERY_OPCODE_SET_FLAG	= 0x6,
	UPIU_QUERY_OPCODE_CLEAR_FLAG	= 0x7,
	UPIU_QUERY_OPCODE_TOGGLE_FLAG	= 0x8,
};

/* bRefClkFreq attribute values */
enum ufs_ref_clk_freq {
	REF_CLK_FREQ_19_2_MHZ	= 0,
	REF_CLK_FREQ_26_MHZ	= 1,
	REF_CLK_FREQ_38_4_MHZ	= 2,
	REF_CLK_FREQ_52_MHZ	= 3,
	REF_CLK_FREQ_INVAL	= -1,
};

/* bDefragOperation attribute values */
enum ufs_hid_defrag_operation {
	HID_ANALYSIS_AND_DEFRAG_DISABLE	= 0,
	HID_ANALYSIS_ENABLE		= 1,
	HID_ANALYSIS_AND_DEFRAG_ENABLE	= 2,
};

/* bHIDState attribute values */
enum ufs_hid_state {
	HID_IDLE		= 0,
	ANALYSIS_IN_PROGRESS	= 1,
	DEFRAG_REQUIRED		= 2,
	DEFRAG_IN_PROGRESS	= 3,
	DEFRAG_COMPLETED	= 4,
	DEFRAG_NOT_REQUIRED	= 5,
	NUM_UFS_HID_STATES	= 6,
};

/* bWriteBoosterBufferResizeEn attribute */
enum wb_resize_en {
	WB_RESIZE_EN_IDLE	= 0,
	WB_RESIZE_EN_DECREASE	= 1,
	WB_RESIZE_EN_INCREASE	= 2,
};

/* bWriteBoosterBufferResizeHint attribute */
enum wb_resize_hint {
	WB_RESIZE_HINT_KEEP	= 0,
	WB_RESIZE_HINT_DECREASE	= 1,
	WB_RESIZE_HINT_INCREASE	= 2,
};

/* bWriteBoosterBufferResizeStatus attribute */
enum wb_resize_status {
	WB_RESIZE_STATUS_IDLE	= 0,
	WB_RESIZE_STATUS_IN_PROGRESS	= 1,
	WB_RESIZE_STATUS_COMPLETE_SUCCESS	= 2,
	WB_RESIZE_STATUS_GENERAL_FAILURE	= 3,
};

/* Query response result code */
enum {
	QUERY_RESULT_SUCCESS                    = 0x00,
	QUERY_RESULT_NOT_READABLE               = 0xF6,
	QUERY_RESULT_NOT_WRITEABLE              = 0xF7,
	QUERY_RESULT_ALREADY_WRITTEN            = 0xF8,
	QUERY_RESULT_INVALID_LENGTH             = 0xF9,
	QUERY_RESULT_INVALID_VALUE              = 0xFA,
	QUERY_RESULT_INVALID_SELECTOR           = 0xFB,
	QUERY_RESULT_INVALID_INDEX              = 0xFC,
	QUERY_RESULT_INVALID_IDN                = 0xFD,
	QUERY_RESULT_INVALID_OPCODE             = 0xFE,
	QUERY_RESULT_GENERAL_FAILURE            = 0xFF,
};

/* UTP Transfer Request Command Type (CT) */
enum {
	UPIU_COMMAND_SET_TYPE_SCSI	= 0x0,
	UPIU_COMMAND_SET_TYPE_UFS	= 0x1,
	UPIU_COMMAND_SET_TYPE_QUERY	= 0x2,
};

/* Offset of the response code in the UPIU header */
#define UPIU_RSP_CODE_OFFSET		8

enum {
	MASK_TM_SERVICE_RESP		= 0xFF,
};

/* Task management service response */
enum {
	UPIU_TASK_MANAGEMENT_FUNC_COMPL		= 0x00,
	UPIU_TASK_MANAGEMENT_FUNC_NOT_SUPPORTED = 0x04,
	UPIU_TASK_MANAGEMENT_FUNC_SUCCEEDED	= 0x08,
	UPIU_TASK_MANAGEMENT_FUNC_FAILED	= 0x05,
	UPIU_INCORRECT_LOGICAL_UNIT_NO		= 0x09,
};

/* UFS device power modes */
enum ufs_dev_pwr_mode {
	UFS_ACTIVE_PWR_MODE	= 1,
	UFS_SLEEP_PWR_MODE	= 2,
	UFS_POWERDOWN_PWR_MODE	= 3,
	UFS_DEEPSLEEP_PWR_MODE	= 4,
};

#define UFS_WB_BUF_REMAIN_PERCENT(val) ((val) / 10)

/**
 * struct utp_cmd_rsp - Response UPIU structure
 * @residual_transfer_count: Residual transfer count DW-3
 * @reserved: Reserved double words DW-4 to DW-7
 * @sense_data_len: Sense data length DW-8 U16
 * @sense_data: Sense data field DW-8 to DW-12
 */
struct utp_cmd_rsp {
	__be32 residual_transfer_count;
	__be32 reserved[4];
	__be16 sense_data_len;
	u8 sense_data[UFS_SENSE_SIZE];
};

/**
 * struct utp_upiu_rsp - general upiu response structure
 * @header: UPIU header structure DW-0 to DW-2
 * @sr: fields structure for scsi command DW-3 to DW-12
 * @qr: fields structure for query request DW-3 to DW-7
 */
struct utp_upiu_rsp {
	struct utp_upiu_header header;
	union {
		struct utp_cmd_rsp sr;
		struct utp_upiu_query qr;
	};
};

/*
 * VCCQ & VCCQ2 current requirement when UFS device is in sleep state
 * and link is in Hibern8 state.
 */
#define UFS_VREG_LPM_LOAD_UA	1000 /* uA */

struct ufs_vreg {
	struct regulator *reg;
	const char *name;
	bool always_on;
	bool enabled;
	int max_uA;
};

struct ufs_vreg_info {
	struct ufs_vreg *vcc;
	struct ufs_vreg *vccq;
	struct ufs_vreg *vccq2;
	struct ufs_vreg *vdd_hba;
};

/* UFS device descriptor wPeriodicRTCUpdate bit9 defines RTC time baseline */
#define UFS_RTC_TIME_BASELINE BIT(9)

enum ufs_rtc_time {
	UFS_RTC_RELATIVE,
	UFS_RTC_ABSOLUTE
};

struct ufs_dev_info {
	bool	f_power_on_wp_en;
	/* Keeps information if any of the LU is power on write protected */
	bool	is_lu_power_on_wp;
	/* Maximum number of general LU supported by the UFS device */
	u8	max_lu_supported;
	u16	wmanufacturerid;
	/*UFS device Product Name */
	u8	*model;
	u16	wspecversion;
	u32	clk_gating_wait_us;
	/* Stores the depth of queue in UFS device */
	u8	bqueuedepth;

	/* UFS WB related flags */
	bool    wb_enabled;
	bool    wb_buf_flush_enabled;
	u8	wb_dedicated_lu;
	u8      wb_buffer_type;
	u16	ext_wb_sup;

	bool	b_rpm_dev_flush_capable;
	u8	b_presrv_uspc_en;

	bool    b_advanced_rpmb_en;

	/* UFS RTC */
	enum ufs_rtc_time rtc_type;
	time64_t rtc_time_baseline;
	u32 rtc_update_period;

	u8 rtt_cap; /* bDeviceRTTCap */

	bool hid_sup;
};

/*
 * This enum is used in string mapping in ufs_trace.h.
 */
enum ufs_trace_str_t {
	UFS_CMD_SEND, UFS_CMD_COMP, UFS_DEV_COMP,
	UFS_QUERY_SEND, UFS_QUERY_COMP, UFS_QUERY_ERR,
	UFS_TM_SEND, UFS_TM_COMP, UFS_TM_ERR
};

/*
 * Transaction Specific Fields (TSF) type in the UPIU package, this enum is
 * used in ufs_trace.h for UFS command trace.
 */
enum ufs_trace_tsf_t {
	UFS_TSF_CDB, UFS_TSF_OSF, UFS_TSF_TM_INPUT, UFS_TSF_TM_OUTPUT
};

#endif /* End of Header */
