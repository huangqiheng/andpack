#ifndef __xml_in_section_h_once__ 
#define __xml_in_section_h_once__

#ifdef __cplusplus
extern "C" {
#endif

const char** get_catelog (const char* xmlstr, const char* catelog_name);
const char** get_keyvalue(const char* xmlstr, const char* catelog_name, const char* key_name);
const char*  set_keyvalue(const char* xmlstr, const char* catelog_name, const char* key_name, const char* value);

const char* image_to_xmlstr(void* image_base, const char* section_name);
const char* file_to_xmlstr(void* file_base, const char* section_name);


#ifdef __cplusplus
}
#endif

#endif
