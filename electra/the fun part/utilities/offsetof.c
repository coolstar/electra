unsigned offsetof_p_pid = 0x10;               // proc_t::p_pid
unsigned offsetof_task = 0x18;                // proc_t::task
unsigned offsetof_p_ucred = 0x100;            // proc_t::p_ucred
unsigned offsetof_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned offsetof_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned offsetof_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned offsetof_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned offsetof_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned offsetof_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned offsetof_p_textvp = 0x248;           // proc_t::p_textvp
unsigned offsetof_p_textoff = 0x250;          // proc_t::p_textoff
unsigned offsetof_p_cputype = 0x2c0;          // proc_t::p_cputype
unsigned offsetof_p_cpu_subtype = 0x2c4;      // proc_t::p_cpu_subtype
unsigned offsetof_special = 2 * sizeof(long); // host::special

unsigned offsetof_v_type = 0x70;              // vnode::v_type
unsigned offsetof_v_id = 0x74;                // vnode::v_id
unsigned offsetof_v_ubcinfo = 0x78;           // vnode::v_ubcinfo
unsigned offsetof_v_mount = 0xd8;             // vnode::v_mount

unsigned offsetof_mnt_flag = 0x70;            // mount::mnt_flag

unsigned offsetof_ubcinfo_csblobs = 0x50;     // ubc_info::csblobs

unsigned offsetof_csb_cputype = 0x8;          // cs_blob::csb_cputype
unsigned offsetof_csb_flags = 0x12;           // cs_blob::csb_flags
unsigned offsetof_csb_base_offset = 0x16;     // cs_blob::csb_base_offset
unsigned offsetof_csb_entitlements_offset = 0x98; // cs_blob::csb_entitlements
unsigned offsetof_csb_signer_type = 0xA0;     // cs_blob::csb_signer_type
unsigned offsetof_csb_platform_binary = 0xA4; // cs_blob::csb_platform_binary
unsigned offsetof_csb_platform_path = 0xA8;   // cs_blob::csb_platform_path
