// multi_dll_loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include <vector>
#include <array>
#include <memory>
#include <thread>
#include "auto_parallel.h"
#include "Dll1.h"


static constexpr int thread_count = 1000;
static constexpr int increment_count = 10000000;
std::array<int, thread_count> thread_results;

void worker_proc(int index) {
    for (int i = 0; i != increment_count; ++i) {
        // update static variable in dll
        int data_from_dll = get_data();
        ++data_from_dll;
        set_data(data_from_dll);
    }
    thread_results[index] = get_data();
}

int main()
{
    // register dlls for use with auto-parallelism
    LPCSTR szDlls[] = { "DLL1.dll" };
    InitAutoParallelDll(szDlls, _countof(szDlls));




    std::vector<std::thread> threads;

    // start threads
    for (int index = 0; index != thread_count; ++index) {
        threads.emplace_back(worker_proc, index);
    }

    // join all
    for (int index = 0; index != thread_count; ++index) {
        threads[index].join();
    }


    for (int index = 0; index != thread_count; ++index) {
        if (thread_results[index] != increment_count) {
            std::cout << "Bad things happened!\n";
            return -1;
        }
    }

    std::cout << "No errors found!\n";
    return 0;
}

