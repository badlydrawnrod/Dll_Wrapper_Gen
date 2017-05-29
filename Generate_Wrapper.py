from __future__ import print_function

import os.path
import sys
import subprocess
import shutil
import time


main_template = """\
#include <windows.h>
#include <stdio.h>

HINSTANCE mHinst = 0;
HINSTANCE mHinstDLL = 0;

extern "C" UINT_PTR mProcs[%(num_procs)d] = {0};

extern "C" LPCSTR mImportNames[] = {%(import_names)s};


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved) {
	mHinst = hinstDLL;
	if (dwReason == DLL_PROCESS_ATTACH) {
		mHinstDLL = LoadLibrary("ori_%(dll_name)s");
		if (!mHinstDLL)
			return FALSE;
		for (int i = 0; i < sizeof(mProcs) / sizeof(mProcs[0]); i++) {
			mProcs[i] = (UINT_PTR)GetProcAddress( mHinstDLL, mImportNames[i]);
        }
	}
    else if (dwReason == DLL_PROCESS_DETACH) {
		FreeLibrary(mHinstDLL);
	}
	
    return TRUE;
}
"""


def run(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = p.communicate()
    output = output.decode('utf-8')
    return output


def check_architecture(dll_name):
    output = run('dumpbin_tools/dumpbin.exe /headers ' + dll_name)
    if 'x86' in output:
        return 'x86'
    elif 'x64' in output:
        return 'x64'
    return None


def get_export_list(dll_name):
    output = run('dumpbin_tools/dumpbin.exe /exports ' + dll_name)
    lines = output.split('\r\n')

    results = []

    state = 0
    for line in lines:
        if state == 0:
            if 'ordinal' in line and 'hint' in line and 'RVA' in line and 'name' in line:
                state = 1
            continue
        elif state == 1:
            state = 2
            continue
        
        line = line.strip()
        if len(line) is 0:
            break

        fields = line.split()
        if len(fields) > 3 and fields[3] == '(forwarded':
            fields = fields[:-3]

        ordinal = fields[0]
        fcnname = fields[-1]
        results.append((fcnname, ordinal))

    return results


def make_def_file(target_path, dll_name, def_items):
    with open(os.path.join(target_path, dll_name.replace('.dll', '.def')), 'w') as f:
        print('LIBRARY %s' % dll_name, file=f)
        print('EXPORTS', file=f)
        for item in def_items:
            print('\t%s' % item, file=f)


def make_cpp_file(target_path, dll_name, load_names, wrapped_functions):
    main_values = dict(
        num_procs=len(load_names),
        import_names=', '.join('"%s"' % n for n in load_names),
        dll_name=dll_name
        )

    with open(os.path.join(target_path, dll_name.replace('.dll', '.cpp')), 'w') as f:
        print(main_template % main_values, file=f)
    
        if architecture == 'x64':
            for item in wrapped_functions:
                print('extern "C" void %s();' % item, file=f)
        else:
            for idx, item in enumerate(wrapped_functions):
                print('extern "C" __declspec(naked) void __stdcall %s() {__asm{jmp mProcs[%d*4]}}' % (item, idx), file=f)


def make_asm_file(target_path, dll_name, wrapped_functions):
    with open(os.path.join(target_path, dll_name.replace('.dll', '_asm.asm')), 'w') as f:
        print('.code', file=f)
        print('extern mProcs:QWORD', file=f)
        for idx, item in enumerate(wrapped_functions):
            print('%s proc' % item, file=f)
            print('\tjmp mProcs[%d*8]' % idx, file=f)
            print('%s endp' % item, file=f)
        print('end', file=f)


def extract_names(items):
    load_names = []
    wrapped_functions = []
    def_items = []
    
    for function_name, ordinal in items:
        if function_name == '[NONAME]':
            load_names.append('(LPCSTR)' + ordinal)
            wrapped_functions.append('ExportByOrdinal' + ordinal)
            def_items.append('ExportByOrdinal%s @%s NONAME' % (ordinal, ordinal))
        else:
            load_names.append(function_name)
            wrapped_functions.append(function_name + '_wrapper')
            def_items.append('%s=%s_wrapper @%s' % (function_name, function_name, ordinal))

    return def_items, load_names, wrapped_functions


def make_solution_directory(solution_dir, proj_name):
    if os.path.exists(solution_dir):
        shutil.rmtree(solution_dir)
    time.sleep(2)   # TODO: why?
    os.makedirs(os.path.join(solution_dir, proj_name))


def make_solution(dll_path, architecture, items):
    def_items, load_names, wrapped_functions = extract_names(items)

    dll_name = os.path.basename(dll_path)
    dll_basename = dll_name[:-4]

    src_path = os.path.join('Visual Studio Project Template', architecture)

    solution_dir = dll_basename
    make_solution_directory(solution_dir, dll_basename)
    proj_dir = os.path.join(solution_dir, dll_basename)

    def transform(src, dst):
        with open(src, 'r') as srcfile:
            with open(dst, 'w') as dstfile:
                for line in srcfile:
                    line = line.replace('MyName', dll_basename)
                    line = line.replace('MYNAME', dll_basename.upper())
                    dstfile.write(line)

    transform(os.path.join(src_path, 'MyName.sln'), os.path.join(solution_dir, dll_basename + '.sln'))
    transform(os.path.join(src_path, 'MyName', 'MyName.vcxproj'), os.path.join(proj_dir, dll_basename + '.vcxproj'))
    transform(os.path.join(src_path, 'MyName', 'MyName.vcxproj.filters'), os.path.join(proj_dir, dll_basename + '.vcxproj.filters'))
    transform(os.path.join(src_path, 'MyName', 'MyName.vcxproj.user'), os.path.join(proj_dir, dll_basename + '.vcxproj.user'))
    
    shutil.copy(os.path.join(src_path, 'MyName.suo'), os.path.join(solution_dir, dll_basename + '.suo'))

    print('Generating .cpp file...')
    make_cpp_file(proj_dir, dll_name, load_names, wrapped_functions)

    print('Generating .def file...')    
    make_def_file(proj_dir, dll_name, def_items)
    
    if architecture == 'x64':
        print('Generating .asm file...')
        make_asm_file(proj_dir, dll_name, wrapped_functions)


if __name__ == '__main__':
    print('Wrapper Generator. Copyright (C) Lin Min\n')

    if len(sys.argv) != 2:
        print('You should pass a dll file to this program.')
        sys.exit(1)

    dll_path = sys.argv[1]
    if not dll_path.lower().endswith('.dll'):
        print('You should pass a dll file to this program.')
        sys.exit(1)

    if not os.path.exists(dll_path):
        print('The specified file "%s" does not exist.' % dll_path)
        sys.exit(1)

    print('Checking architecture...', end='')
    architecture = check_architecture(dll_path)
    if architecture == 'x86' or architecture == 'x64':
        print('%s dll detected.' % architecture)
    else:
        print('invalid dll file, exiting ...')
        sys.exit(1)

    print('Scanning exports...')
    items = get_export_list(dll_path)

    print('Writing solution...')    
    make_solution(dll_path, architecture, items)
