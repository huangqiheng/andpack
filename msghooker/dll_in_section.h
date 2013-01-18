#ifndef __dll_in_section_h_once__
#define __dll_in_section_h_once__

#ifdef __cplusplus
extern "C" {
#endif


PIMAGE_SECTION_HEADER get_spectial_section_byname(void* pe_base, const char *section_name);
int is_section_exists(void* pe_base, const char* section_name);
int is_section_exists_main(const char* section_name);
int is_section_exists_me(const char* section_name);

HMODULE get_module_base();
void* get_section_me(const char* section_name);
void* get_section(void* pe_base, const char* section_name);
void* get_section_raw(void* file_base, const char* section_name);

STARTUP* get_startup_section_me();
PACKAGE* get_package_section_me();
void* get_storepe_section_me();

PACKAGE* get_package_section_main();
STARTUP* get_startup_section_main();
void* get_section_main(const char* section_name);

char* whoiam_realy_name(PACKAGE* package);
char* whoiam_realy_name_me();

int section_to_file(const char* src_file, const char* section_name, const char* to_file);

long append_section_try(const void* target_file_base, long *section_va, long *section_raw);
void* append_section_raw(const void* target_file_base, long target_file_size, long* output_file_size,
		const char *SectionName, const void *NewRawData, long NewRawSize, long NewVirtualSize, long Characteristics);

void* append_section(const void* target_file_base, long target_file_size, long* output_file_size, 
		const char *section_name, const void* section_data, long section_size);

void* append_section_mainpe(const void* target_file_base, long target_file_size, long* output_file_size, 
		const char *section_name, const void* pe_to_pack, long pe_size);


#ifdef __cplusplus
}
#endif

#endif
