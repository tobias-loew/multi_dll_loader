// Dll1.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "Dll1.h"

// static variable
int data=0;

DLL1_API int get_data() {
    return data;
}

DLL1_API void set_data(int n) {
    data = n;
}
