// embedded.cpp
unsigned char dll_buf[] = { 0x4D, 0x5A}; // from xxd or bin2h "xxd -i my.dll > embedded.cpp"
size_t dll_buf_len = sizeof(dll_buf);
