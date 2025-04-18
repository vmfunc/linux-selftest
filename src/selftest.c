// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/vmalloc.h>
#include <asm/processor.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/set_memory.h>
#include <asm/setup.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

/* Module information */
MODULE_AUTHOR("vmfunc <mel@ud2.rip>");
MODULE_DESCRIPTION("Linux Kernel Self-Test Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_func;

struct build_test_info {
    const char *component;
    const char *description;
    bool (*test_fn)(void);
};

/* test results */
static struct dentry *security_test_dir;
static struct kobject *security_test_kobj;
static DEFINE_MUTEX(test_results_lock);

#define MAX_RESULT_SIZE 4096
#define MAX_SINGLE_RESULT 256

struct test_result {
    const char *component;
    const char *description;
    bool passed;
    char details[MAX_SINGLE_RESULT];
};

static struct test_result *all_results;
static int total_tests;

static bool test_basic_alloc(void)
{
    void *ptr = kmalloc(1024, GFP_KERNEL);
    if (!ptr)
        return false;
    kfree(ptr);
    return true;
}

static bool test_config_sanity(void)
{
    #ifdef CONFIG_SMP
    if (num_possible_cpus() < 1)
        return false;
    #endif
    return true;
}

static bool test_stack_protector(void)
{
    #ifdef CONFIG_STACKPROTECTOR
    return true;
    #else
    pr_warn("selftest: Stack protector is not enabled\n");
    return false;
    #endif
}

static bool test_kaslr(void)
{
    #ifdef CONFIG_RANDOMIZE_BASE
    return true;
    #else
    pr_warn("selftest: Kernel Address Space Layout Randomization (KASLR) is not enabled\n");
    return false;
    #endif
}

static bool test_page_table_isolation(void)
{
    #ifdef CONFIG_PAGE_TABLE_ISOLATION
    return true;
    #else
    pr_warn("selftest: Page Table Isolation (PTI/KPTI) is not enabled\n");
    return false;
    #endif
}

static bool test_smap_smep(void)
{
    bool has_security = false;
    #ifdef CONFIG_X86_SMAP
    has_security = true;
    #else
    pr_warn("selftest: Supervisor Mode Access Prevention (SMAP) is not enabled\n");
    #endif
    
    #ifdef CONFIG_X86_SMEP
    has_security = has_security && true;
    #else
    pr_warn("selftest: Supervisor Mode Execution Prevention (SMEP) is not enabled\n");
    has_security = false;
    #endif
    
    return has_security;
}

static bool test_hardened_usercopy(void)
{
    #ifdef CONFIG_HARDENED_USERCOPY
    return true;
    #else
    pr_warn("selftest: Hardened usercopy is not enabled\n");
    return false;
    #endif
}

static bool test_init_on_free(void)
{
    #ifdef CONFIG_INIT_ON_FREE_DEFAULT_ON
    return true;
    #else
    pr_warn("selftest: Initialize memory on free is not enabled by default\n");
    return false;
    #endif
}

static bool test_fortify_source(void)
{
    #ifdef CONFIG_FORTIFY_SOURCE
    return true;
    #else
    pr_warn("selftest: Fortify Source is not enabled\n");
    return false;
    #endif
}

static bool verify_read_only_text_section(void)
{
    unsigned char *ptr;
    bool ret = true;
    unsigned long addr;

    addr = (unsigned long)verify_read_only_text_section;
    ptr = (unsigned char *)addr;

    unsigned char test_val = 0x42;
    if (copy_to_kernel_nofault(ptr, &test_val, 1) == 0) {
        pr_err("selftest: Text section is writable!\n");
        ret = false;
    }

    return ret;
}

static bool test_kernel_symbol_protection(void)
{
    unsigned long addr;
    bool protected = true;

    if (!kallsyms_lookup_name_func) {
        pr_err("selftest: kallsyms_lookup_name not available\n");
        return false;
    }

    addr = kallsyms_lookup_name_func("sys_call_table");
    if (addr != 0) {
        pr_err("selftest: sys_call_table symbol is exposed!\n");
        protected = false;
    }

    addr = kallsyms_lookup_name_func("do_init_module");
    if (addr != 0) {
        pr_err("selftest: do_init_module symbol is exposed!\n");
        protected = false;
    }

    return protected;
}

static bool test_stack_canary_randomization(void)
{
    #ifdef CONFIG_STACKPROTECTOR
    unsigned long canary1, canary2;
    int i;
    bool randomized = false;
    unsigned long *canary_ptr;

    /* get the address of the stack canary from thread info */
    canary_ptr = (unsigned long *)current_thread_info();
    if (!canary_ptr)
        return false;

    /* sample stack canaries across multiple stack frames */
    for (i = 0; i < 5; i++) {
        canary1 = *canary_ptr;
        schedule(); /* force stack switch */
        canary2 = *canary_ptr;
        
        if (canary1 != canary2) {
            randomized = true;
            break;
        }
    }

    if (!randomized) {
        pr_err("selftest: Stack canaries may not be properly randomized\n");
        return false;
    }
    return true;
    #else
    return false;
    #endif
}

static bool test_memory_permissions(void)
{
    void *ptr;
    bool ret = true;
    unsigned long page_size = PAGE_SIZE;
    unsigned char test_val = 0x42;

    ptr = vmalloc(page_size);
    if (!ptr)
        return false;

    if (copy_to_kernel_nofault(ptr, &test_val, 1) != 0) {
        pr_err("selftest: Initial memory write failed\n");
        ret = false;
        goto out;
    }

    #ifdef CONFIG_SET_MEMORY_RO
    if (set_memory_ro((unsigned long)ptr, 1) != 0) {
        pr_err("selftest: Failed to set memory read-only\n");
        ret = false;
        goto out;
    }

    if (copy_to_kernel_nofault(ptr, &test_val, 1) == 0) {
        pr_err("selftest: Write to read-only memory succeeded!\n");
        ret = false;
    }
    #endif

    #ifdef CONFIG_SET_MEMORY_NX
    if (set_memory_nx((unsigned long)ptr, 1) != 0) {
        pr_err("selftest: Failed to set memory non-executable\n");
        ret = false;
    }
    #endif

out:
    #ifdef CONFIG_SET_MEMORY_RO
    /* reset to RW before freeing */
    set_memory_rw((unsigned long)ptr, 1);
    #endif
    vfree(ptr);
    return ret;
}

static bool test_kernel_image_integrity(void)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *hash_result;
    int err;
    bool ret = false;
    unsigned long addr;

    /* Use an already defined function's address */
    addr = (unsigned long)test_basic_alloc;

    /* SHA-256 transform */
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("selftest: Failed to allocate SHA-256 transform\n");
        return false;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return false;
    }

    hash_result = kmalloc(32, GFP_KERNEL); /* SHA-256 produces 32 bytes */
    if (!hash_result) {
        kfree(desc);
        crypto_free_shash(tfm);
        return false;
    }

    desc->tfm = tfm;

    err = crypto_shash_init(desc);
    if (err) {
        goto out;
    }

    err = crypto_shash_update(desc, (const u8 *)addr, PAGE_SIZE);
    if (err) {
        goto out;
    }

    err = crypto_shash_final(desc, hash_result);
    if (err) {
        goto out;
    }

    ret = true;

    pr_info("selftest: Kernel text section SHA-256:");
    print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
                  hash_result, 32, true);

out:
    kfree(hash_result);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

static const struct build_test_info build_tests[] = {
    {
        .component = "memory",
        .description = "Basic memory allocation",
        .test_fn = test_basic_alloc,
    },
    {
        .component = "config",
        .description = "Configuration sanity check",
        .test_fn = test_config_sanity,
    },
    {
        .component = "security",
        .description = "Stack protector",
        .test_fn = test_stack_protector,
    },
    {
        .component = "security",
        .description = "Kernel Address Space Layout Randomization",
        .test_fn = test_kaslr,
    },
    {
        .component = "security",
        .description = "Page Table Isolation",
        .test_fn = test_page_table_isolation,
    },
    {
        .component = "security",
        .description = "SMAP/SMEP Protection",
        .test_fn = test_smap_smep,
    },
    {
        .component = "security",
        .description = "Hardened Usercopy",
        .test_fn = test_hardened_usercopy,
    },
    {
        .component = "security",
        .description = "Initialize memory on free",
        .test_fn = test_init_on_free,
    },
    {
        .component = "security",
        .description = "Fortify Source",
        .test_fn = test_fortify_source,
    },
    {
        .component = "security",
        .description = "Kernel text section protection",
        .test_fn = verify_read_only_text_section,
    },
    {
        .component = "security",
        .description = "Kernel symbol protection",
        .test_fn = test_kernel_symbol_protection,
    },
    {
        .component = "security",
        .description = "Stack canary randomization",
        .test_fn = test_stack_canary_randomization,
    },
    {
        .component = "security",
        .description = "Memory permissions enforcement",
        .test_fn = test_memory_permissions,
    },
    {
        .component = "security",
        .description = "Kernel image integrity",
        .test_fn = test_kernel_image_integrity,
    },
};

static void store_test_result(const char *component, const char *description, 
                            bool passed, const char *details)
{
    mutex_lock(&test_results_lock);
    
    if (all_results && total_tests < ARRAY_SIZE(build_tests)) {
        struct test_result *result = &all_results[total_tests++];
        result->component = component;
        result->description = description;
        result->passed = passed;
        if (details)
            strscpy(result->details, details, MAX_SINGLE_RESULT);
        else
            result->details[0] = '\0';
    }
    
    mutex_unlock(&test_results_lock);
}

/* sysfs */
static ssize_t test_results_show(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
    int i;
    size_t len = 0;
    
    mutex_lock(&test_results_lock);
     
    for (i = 0; i < total_tests && len < PAGE_SIZE; i++) {
        struct test_result *result = &all_results[i];
        len += scnprintf(buf + len, PAGE_SIZE - len,
                        "%s - %s: %s\n%s%s\n",
                        result->component,
                        result->description,
                        result->passed ? "PASSED" : "FAILED",
                        result->details[0] ? "Details: " : "",
                        result->details);
    }
    
    mutex_unlock(&test_results_lock);
    return len;
}

static struct kobj_attribute test_results_attr = 
    __ATTR_RO(test_results);

/* debugfs */
static int security_test_results_show(struct seq_file *m, void *v)
{
    int i;
    
    mutex_lock(&test_results_lock);
     
    for (i = 0; i < total_tests; i++) {
        struct test_result *result = &all_results[i];
        seq_printf(m, "Test: %s - %s\n", 
                  result->component, result->description);
        seq_printf(m, "Status: %s\n", 
                  result->passed ? "PASSED" : "FAILED");
        if (result->details[0])
            seq_printf(m, "Details: %s\n", result->details);
        seq_puts(m, "-------------------\n");
    }
    
    mutex_unlock(&test_results_lock);
    return 0;
}

static int security_test_results_open(struct inode *inode, struct file *file)
{
    return single_open(file, security_test_results_show, NULL);
}

static const struct file_operations security_test_fops = {
    .owner = THIS_MODULE,
    .open = security_test_results_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init selftest_init(void)
{
    int ret;
    int i, failed = 0;
    const int nr_tests = ARRAY_SIZE(build_tests);
    
    all_results = kzalloc(sizeof(struct test_result) * nr_tests, GFP_KERNEL);
    if (!all_results)
        return -ENOMEM;

    security_test_kobj = kobject_create_and_add("selftest", kernel_kobj);
    if (!security_test_kobj) {
        pr_err("selftest: Failed to create sysfs entry\n");
        kfree(all_results);
        return -ENOMEM;
    }

    if (sysfs_create_file(security_test_kobj, &test_results_attr.attr)) {
        pr_err("selftest: Failed to create sysfs file\n");
        kobject_put(security_test_kobj);
        kfree(all_results);
        return -ENOMEM;
    }

    security_test_dir = debugfs_create_dir("selftest", NULL);
    if (!security_test_dir) {
        pr_err("selftest: Failed to create debugfs directory\n");
        sysfs_remove_file(security_test_kobj, &test_results_attr.attr);
        kobject_put(security_test_kobj);
        kfree(all_results);
        return -ENOMEM;
    }

    if (!debugfs_create_file("results", 0444, security_test_dir, NULL,
                            &security_test_fops)) {
        pr_err("selftest: Failed to create debugfs file\n");
        debugfs_remove_recursive(security_test_dir);
        sysfs_remove_file(security_test_kobj, &test_results_attr.attr);
        kobject_put(security_test_kobj);
        kfree(all_results);
        return -ENOMEM;
    }

    pr_info("selftest: Starting kernel self-tests...\n");

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("selftest: kprobe registration failed\n");
        return ret;
    }
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);

    for (i = 0; i < nr_tests; i++) {
        const struct build_test_info *test = &build_tests[i];
        bool result;
        
        pr_info("selftest: Running test: %s - %s\n", 
                test->component, test->description);
        
        result = test->test_fn();
        if (!result) {
            pr_err("selftest: Test failed: %s\n", test->component);
            failed++;
        }
        
        store_test_result(test->component, test->description, result,
                         result ? NULL : "Test failed - see kernel log for details");
    }

    if (failed) {
        pr_err("selftest: %d of %d tests failed\n", failed, nr_tests);
        if (failed > nr_tests / 2)
            pr_err("[!] System may be insecure!");
    }
    else
        pr_info("selftest: All %d tests passed\n", nr_tests);

    return 0;
}

static void __exit selftest_exit(void)
{
    debugfs_remove_recursive(security_test_dir);
    sysfs_remove_file(security_test_kobj, &test_results_attr.attr);
    kobject_put(security_test_kobj);
    kfree(all_results);
    pr_info("selftest: Kernel self-tests complete\n");
}

module_init(selftest_init);
module_exit(selftest_exit); 