// SPDX-License-Identifier: GPL-2.0+
/*
 * driver/base/topology.c - Populate sysfs with cpu topology information
 *
 * Written by: Zhang Yanmin, Intel Corporation
 *
 * Copyright (C) 2006, Intel Corp.
 *
 * All rights reserved.
 */
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/hardirq.h>
#include <linux/topology.h>

#define define_id_show_func(name, fmt)					\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr, char *buf)	\
{									\
	return sysfs_emit(buf, fmt "\n", topology_##name(dev->id));	\
}

#define define_siblings_read_func(name, mask)					\
static ssize_t name##_read(struct file *file, struct kobject *kobj,		\
			   const struct bin_attribute *attr, char *buf,		\
			   loff_t off, size_t count)				\
{										\
	struct device *dev = kobj_to_dev(kobj);                                 \
	cpumask_var_t mask;							\
	ssize_t n;								\
										\
	if (!alloc_cpumask_var(&mask, GFP_KERNEL))				\
		return -ENOMEM;							\
										\
	cpumask_copy(mask, topology_##mask(dev->id));				\
	n = cpumap_print_bitmask_to_buf(buf, mask, off, count);			\
	free_cpumask_var(mask);							\
										\
	return n;								\
}										\
										\
static ssize_t name##_list_read(struct file *file, struct kobject *kobj,	\
				const struct bin_attribute *attr, char *buf,	\
				loff_t off, size_t count)			\
{										\
	struct device *dev = kobj_to_dev(kobj);					\
	cpumask_var_t mask;							\
	ssize_t n;								\
										\
	if (!alloc_cpumask_var(&mask, GFP_KERNEL))				\
		return -ENOMEM;							\
										\
	cpumask_copy(mask, topology_##mask(dev->id));				\
	n = cpumap_print_list_to_buf(buf, mask, off, count);			\
	free_cpumask_var(mask);							\
										\
	return n;								\
}

define_id_show_func(physical_package_id, "%d");
static DEVICE_ATTR_RO(physical_package_id);

#ifdef TOPOLOGY_DIE_SYSFS
define_id_show_func(die_id, "%d");
static DEVICE_ATTR_RO(die_id);
#endif

#ifdef TOPOLOGY_CLUSTER_SYSFS
define_id_show_func(cluster_id, "%d");
static DEVICE_ATTR_RO(cluster_id);
#endif

define_id_show_func(core_id, "%d");
static DEVICE_ATTR_RO(core_id);

define_id_show_func(ppin, "0x%llx");
static DEVICE_ATTR_ADMIN_RO(ppin);

define_siblings_read_func(thread_siblings, sibling_cpumask);
static const BIN_ATTR_RO(thread_siblings, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(thread_siblings_list, CPULIST_FILE_MAX_BYTES);

define_siblings_read_func(core_cpus, sibling_cpumask);
static const BIN_ATTR_RO(core_cpus, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(core_cpus_list, CPULIST_FILE_MAX_BYTES);

define_siblings_read_func(core_siblings, core_cpumask);
static const BIN_ATTR_RO(core_siblings, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(core_siblings_list, CPULIST_FILE_MAX_BYTES);

#ifdef TOPOLOGY_CLUSTER_SYSFS
define_siblings_read_func(cluster_cpus, cluster_cpumask);
static const BIN_ATTR_RO(cluster_cpus, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(cluster_cpus_list, CPULIST_FILE_MAX_BYTES);
#endif

#ifdef TOPOLOGY_DIE_SYSFS
define_siblings_read_func(die_cpus, die_cpumask);
static const BIN_ATTR_RO(die_cpus, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(die_cpus_list, CPULIST_FILE_MAX_BYTES);
#endif

define_siblings_read_func(package_cpus, core_cpumask);
static const BIN_ATTR_RO(package_cpus, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(package_cpus_list, CPULIST_FILE_MAX_BYTES);

#ifdef TOPOLOGY_BOOK_SYSFS
define_id_show_func(book_id, "%d");
static DEVICE_ATTR_RO(book_id);
define_siblings_read_func(book_siblings, book_cpumask);
static const BIN_ATTR_RO(book_siblings, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(book_siblings_list, CPULIST_FILE_MAX_BYTES);
#endif

#ifdef TOPOLOGY_DRAWER_SYSFS
define_id_show_func(drawer_id, "%d");
static DEVICE_ATTR_RO(drawer_id);
define_siblings_read_func(drawer_siblings, drawer_cpumask);
static const BIN_ATTR_RO(drawer_siblings, CPUMAP_FILE_MAX_BYTES);
static const BIN_ATTR_RO(drawer_siblings_list, CPULIST_FILE_MAX_BYTES);
#endif

static const struct bin_attribute *const bin_attrs[] = {
	&bin_attr_core_cpus,
	&bin_attr_core_cpus_list,
	&bin_attr_thread_siblings,
	&bin_attr_thread_siblings_list,
	&bin_attr_core_siblings,
	&bin_attr_core_siblings_list,
#ifdef TOPOLOGY_CLUSTER_SYSFS
	&bin_attr_cluster_cpus,
	&bin_attr_cluster_cpus_list,
#endif
#ifdef TOPOLOGY_DIE_SYSFS
	&bin_attr_die_cpus,
	&bin_attr_die_cpus_list,
#endif
	&bin_attr_package_cpus,
	&bin_attr_package_cpus_list,
#ifdef TOPOLOGY_BOOK_SYSFS
	&bin_attr_book_siblings,
	&bin_attr_book_siblings_list,
#endif
#ifdef TOPOLOGY_DRAWER_SYSFS
	&bin_attr_drawer_siblings,
	&bin_attr_drawer_siblings_list,
#endif
	NULL
};

static struct attribute *default_attrs[] = {
	&dev_attr_physical_package_id.attr,
#ifdef TOPOLOGY_DIE_SYSFS
	&dev_attr_die_id.attr,
#endif
#ifdef TOPOLOGY_CLUSTER_SYSFS
	&dev_attr_cluster_id.attr,
#endif
	&dev_attr_core_id.attr,
#ifdef TOPOLOGY_BOOK_SYSFS
	&dev_attr_book_id.attr,
#endif
#ifdef TOPOLOGY_DRAWER_SYSFS
	&dev_attr_drawer_id.attr,
#endif
	&dev_attr_ppin.attr,
	NULL
};

static umode_t topology_is_visible(struct kobject *kobj,
				   struct attribute *attr, int unused)
{
	if (attr == &dev_attr_ppin.attr && !topology_ppin(kobj_to_dev(kobj)->id))
		return 0;

	return attr->mode;
}

static const struct attribute_group topology_attr_group = {
	.attrs = default_attrs,
	.bin_attrs = bin_attrs,
	.is_visible = topology_is_visible,
	.name = "topology"
};

/* Add/Remove cpu_topology interface for CPU device */
static int topology_add_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	return sysfs_create_group(&dev->kobj, &topology_attr_group);
}

static int topology_remove_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	sysfs_remove_group(&dev->kobj, &topology_attr_group);
	return 0;
}

static int __init topology_sysfs_init(void)
{
	return cpuhp_setup_state(CPUHP_TOPOLOGY_PREPARE,
				 "base/topology:prepare", topology_add_dev,
				 topology_remove_dev);
}

device_initcall(topology_sysfs_init);

DEFINE_PER_CPU(unsigned long, cpu_scale) = SCHED_CAPACITY_SCALE;
EXPORT_PER_CPU_SYMBOL_GPL(cpu_scale);

void topology_set_cpu_scale(unsigned int cpu, unsigned long capacity)
{
	per_cpu(cpu_scale, cpu) = capacity;
}

static ssize_t cpu_capacity_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cpu *cpu = container_of(dev, struct cpu, dev);

	return sysfs_emit(buf, "%lu\n", topology_get_cpu_scale(cpu->dev.id));
}

static DEVICE_ATTR_RO(cpu_capacity);

static int cpu_capacity_sysctl_add(unsigned int cpu)
{
	struct device *cpu_dev = get_cpu_device(cpu);

	if (!cpu_dev)
		return -ENOENT;

	device_create_file(cpu_dev, &dev_attr_cpu_capacity);

	return 0;
}

static int cpu_capacity_sysctl_remove(unsigned int cpu)
{
	struct device *cpu_dev = get_cpu_device(cpu);

	if (!cpu_dev)
		return -ENOENT;

	device_remove_file(cpu_dev, &dev_attr_cpu_capacity);

	return 0;
}

static int register_cpu_capacity_sysctl(void)
{
	cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "topology/cpu-capacity",
			  cpu_capacity_sysctl_add, cpu_capacity_sysctl_remove);

	return 0;
}
subsys_initcall(register_cpu_capacity_sysctl);
