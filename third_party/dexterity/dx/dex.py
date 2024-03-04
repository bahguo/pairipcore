from third_party.dexterity.dx.dxlib import dxlib
from third_party.dexterity.dx.dxlib import _Dex
from third_party.dexterity.dx.bytestream import ByteStream

class Dex(object):
    def __init__(self,filename):
        if filename == None: 
            raise(Exception("Null File Name."))

        self.bs = ByteStream(filename)
        
        self._dex = dxlib.dx_parse(self.bs._bs)

    def save(self,filename):
        if filename == None: 
            raise(Exception("Null File Name."))

        dxlib.dx_build(self._dex,filename)

    def shift_offset(self,base,delta):
        dxlib.dx_shift_offset(self._dex,base,delta)

    def shift_stringid(self,base,delta):
        dxlib.dx_shift_stringif(self._dex,base,delta)    

    def add_string(self,string):
        str_id_offset = dxlib.dx_string_add(self._dex,string)
        return str_id_offset

    #Data 
    def header(self):
        return self._dex.contents.header.contents

    def meta(self):
        return self._dex.contents.meta
    
    def contents(self):
        return self._dex.contents

    def map_list(self):
        return self._dex.contents.map_list.contents

    def string_ids(self):
        return [self._dex.contents.string_ids[i].contents
                for i in range(self._dex.contents.header.contents.string_ids_size)]

    def type_ids(self):
        return [self._dex.contents.type_ids[i].contents
                for i in range(self._dex.contents.header.contents.type_ids_size)]

    def proto_ids(self):
        return [self._dex.contents.proto_ids[i].contents
                for i in range(self._dex.contents.header.contents.proto_ids_size)]

    def field_ids(self):
        return [self._dex.contents.field_ids[i].contents 
                for i in range(self._dex.contents.header.contents.field_ids_size)]

    def method_ids(self):
        return [self._dex.contents.method_ids[i].contents
                for i in range(self._dex.contents.header.contents.method_ids_size)]

    def class_defs(self):
        return [self._dex.contents.class_defs[i].contents
                for i in range(self._dex.contents.header.contents.class_defs_size)]

    def type_lists(self):
        return [self._dex.contents.type_lists[i].contents
                for i in range(self._dex.contents.meta.type_lists_size)]

    def string_data_list(self):
        return [self._dex.contents.string_data_list[i].contents
                for i in range(self._dex.contents.header.contents.string_ids_size)]

    def class_data(self):
        class_data_size = self._dex.contents.meta.class_data_size
        return class_data_size, [self._dex.contents.class_data[i].contents
                for i in range(class_data_size)]                

    def direct_class_data_list(self):
        return [self._dex.contents.class_data[i].contents.direct_methods
                for i in range(self._dex.contents.meta.class_data_size)]

    def virtual_class_data_list(self):
        return [self._dex.contents.class_data[i].contents.virtual_methods
                for i in range(self._dex.contents.meta.class_data_size)]

    def code_list(self):
        return [self._dex.contents.code_list[i].contents
                for i in range(self._dex.contents.meta.code_list_size)]

    def debug_info_list(self):
        return [self._dex.contents.debug_info_list[i].contents
                for i in range(self._dex.contents.meta.debug_info_list_size)]

    def encoded_arrays(self):
        return [self._dex.contents.encoded_arrays[i].contents
                for i in range(self._dex.contents.meta.encoded_arrays_size)]

    def an_directories(self):
        return [self._dex.contents.an_directories[i].contents
                for i in range(self._dex.contents.meta.an_directories_size)]

    def an_set_ref_lists(self):
        return [self._dex.contents.an_set_ref_lists[i].contents
                for i in range(self._dex.contents.meta.an_set_ref_lists_size)]

    def an_set(self):
        return [self._dex.contents.an_set[i].contents
                for i in range(self._dex.contents.meta.an_set_size)]

    def annotations(self):
        return [self._dex.contents.annotations[i].contents
                for i in range(self._dex.contents.meta.annotations_size)]
