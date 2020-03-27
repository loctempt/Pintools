/*
 * Copyright 2002-2019 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <ctime>
#include <unordered_map>
#include <cstring>
#include "pin.H"
// #include "types_vmapi.H"
using std::cerr;
using std::dec;
using std::endl;
using std::hex;
using std::ios;
using std::left;
using std::ofstream;
using std::setw;
using std::showbase;
using std::string;
using std::time;
using std::unordered_map;
using std::vector;

ofstream mapFile; //MapFile;
// vector<char *> imageNames;
vector<ofstream *> funcOutFiles, instOutFiles;
unordered_map<string, int> image2idx;
string prevFunc;
int outFileIndex = 0;
ADDRINT returnAddress = 0;

#define MALLOC "malloc"
#define CALLOC "calloc"
#define REALLOC "realloc"
#define FREE "free"

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;

VOID printTimestamp(ofstream *ofs)
{
    (*ofs) << dec << setw(10) << left << icount++;
}

//============================================
//      Begining of instruction operations
//============================================
// This function is called before every instruction is executed

VOID recordWriteIns(ADDRINT ptr, int fileIdx)
{
    printTimestamp(instOutFiles[fileIdx]);
    (*(instOutFiles[fileIdx])) << hex << showbase
                               << "w @ " << ptr << endl;
}

VOID recordReadIns(ADDRINT ptr, int fileIdx)
{
    printTimestamp(instOutFiles[fileIdx]);
    (*(instOutFiles[fileIdx])) << hex << showbase
                               << "r @ " << ptr << endl;
}

VOID printIns(ADDRINT val, int fileIdx)
{
    // PIN_REGISTER reg_val;
    // PIN_GetContextRegval(ctxt, REG_RAX, reinterpret_cast<UINT8 *>(&reg_val));
    // UINT64 val = reinterpret_cast<UINT64>(reg_val.qword);
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << "   returns: " << val << endl;
}
//============================================
//      End of instruction operations
//============================================

//============================================
//      Begining of function operations
//============================================
VOID MallocBefore(CHAR *name, int fileIdx, ADDRINT returnAddr, ADDRINT size)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << " " << name << "(" << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

// VOID MallocAfter(CHAR *name, CHAR *imgName, ADDRINT ret)
// {
//     funcOutFile << hex << showbase
//                 << "\t" << name << "  returns " << ret
//                 << "\t\t" << imgName << endl;
// }

VOID CallocBefore(CHAR *name, int fileIdx, ADDRINT returnAddr, ADDRINT nmemb, ADDRINT size)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << " " << name << "(" << nmemb << ", " << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

// VOID CallocAfter(CHAR *name, CHAR *imgName, ADDRINT ret)
// {
//     MallocAfter(name, imgName, ret);
// }

VOID ReallocBefore(CHAR *name, int fileIdx, ADDRINT returnAddr, ADDRINT ptr, ADDRINT size)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << " " << name << "(" << ptr << ", " << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

// VOID ReallocAfter(CHAR *name, CHAR *imgName, ADDRINT ret)
// {
//     MallocAfter(name, imgName, ret);
// }

VOID FreeBefore(CHAR *name, int fileIdx, ADDRINT ptr)
{
    MallocBefore(name, fileIdx, 0, ptr);
}
//============================================
//      End of function operations
//============================================

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    RTN rtn = INS_Rtn(ins);
    if (!RTN_Valid(rtn))
        return;
    SEC sec = RTN_Sec(rtn);
    if (!SEC_Valid(sec))
        return;
    IMG img = SEC_Img(sec);
    if (!IMG_Valid(img))
        return;
    string imgName = IMG_Name(img);
    if (image2idx.count(imgName) == 0)
        return;
    int fileIdx = image2idx[imgName];
    // cerr << " file idx = " << fileIdx << endl;
    // Insert a call at function return point, getting
    // the function's return value by reading EAX/RAX.
    if (INS_Address(ins) == returnAddress)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printIns,
#ifdef __i386__
                       IARG_REG_VALUE, REG_EAX,
#else
                       IARG_REG_VALUE, REG_RAX,
#endif
                       IARG_UINT32, fileIdx,
                       IARG_END);

    // Insert a call before both READ and WRITE instructions,
    // their address are passed.
    if (INS_IsMemoryRead(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordReadIns,
                       IARG_MEMORYREAD_EA,
                       IARG_UINT32, fileIdx,
                       IARG_END);
    }
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordWriteIns,
                       IARG_MEMORYWRITE_EA,
                       IARG_UINT32, fileIdx,
                       IARG_END);
    }
}

VOID instFunc(IMG &img, SYM &sym, string &funcName)
{
    // char *imgName = imageNames[imgNameIdx];
    int fileIdx = image2idx[IMG_Name(img)];
    RTN funcRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
    if (!RTN_Valid(funcRtn))
    {
        return;
    }
    RTN_Open(funcRtn);
    if (funcName == MALLOC)
    {
        RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                       IARG_ADDRINT, MALLOC,
                       IARG_UINT32, fileIdx,
                       IARG_RETURN_IP,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        // RTN_InsertCall(funcRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
        //                IARG_ADDRINT, MALLOC,
        //                IARG_ADDRINT, imgName,
        //                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }
    else if (funcName == CALLOC)
    {
        RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                       IARG_ADDRINT, CALLOC,
                       IARG_UINT32, fileIdx,
                       IARG_RETURN_IP,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        // RTN_InsertCall(funcRtn, IPOINT_AFTER, (AFUNPTR)CallocAfter,
        //                IARG_ADDRINT, CALLOC,
        //                IARG_ADDRINT, imgName,
        //                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }
    else if (funcName == REALLOC)
    {
        RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                       IARG_ADDRINT, REALLOC,
                       IARG_UINT32, fileIdx,
                       IARG_RETURN_IP,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_END);
        // RTN_InsertCall(funcRtn, IPOINT_AFTER, (AFUNPTR)ReallocAfter,
        //                IARG_ADDRINT, REALLOC,
        //                IARG_ADDRINT, imgName,
        //                IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    }
    else if (funcName == FREE)
    {
        RTN_InsertCall(funcRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_ADDRINT, FREE,
                       IARG_UINT32, fileIdx,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
    }
    RTN_Close(funcRtn);
    // RTN mallocRtn = RTN_FindByName(img, MALLOC);
    // RTN callocRtn = RTN_FindByName(img, CALLOC);
    // RTN reallocRtn = RTN_FindByName(img, REALLOC);
    // if (RTN_Valid(mallocRtn))
    // {
    //     RTN_Open(mallocRtn);

    //     // Instrument malloc() to print the input argument value and the return value.
    //     RTN_Close(mallocRtn);
    // }

    // if (RTN_Valid(callocRtn))
    // {
    //     RTN_Open(callocRtn);

    //     RTN_Close(callocRtn);
    // }

    // Find the free() function.
    // RTN freeRtn = RTN_FindByName(img, FREE);
    // if (RTN_Valid(freeRtn))
    // {
    //     RTN_Open(freeRtn);
    //     // Instrument free() to print the input argument value.
    //     RTN_Close(freeRtn);
    // }
}

VOID Image(IMG img, VOID *v)
{
    char outFilename[20];

    ofstream *osf = new ofstream;
    sprintf(outFilename, "%d.func.out", outFileIndex);
    osf->open(outFilename);
    funcOutFiles.push_back(osf);

    osf = new ofstream;
    sprintf(outFilename, "%d.inst.out", outFileIndex);
    osf->open(outFilename);
    instOutFiles.push_back(osf);

    mapFile << outFileIndex << "\t" << IMG_Name(img) << endl;
    image2idx[IMG_Name(img)] = outFileIndex++;
    cerr << IMG_Name(img) << endl;

    // if (IMG_Name(img) != "/lib/x86_64-linux-gnu/libc.so.6")
    // if (IMG_Name(img) != "/root/jxy/villoc/a.out")
    // return;
    // char *buf = new char[256];
    // strncpy(buf, IMG_Name(img).c_str(), 255);
    // imageNames.push_back(buf);

    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        string undecorateFuncName = PIN_UndecorateSymbolName(SYM_Name(sym),
                                                             UNDECORATION_NAME_ONLY);
        // cerr << undecorateFuncName << endl;
        instFunc(img, sym, undecorateFuncName);
    }

    // outFileIndex++;
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", "rwcount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    // OutFile.setf(ios::showbase);
    // OutFile << "Count " << icount << endl;
    // OutFile.close();
    // for (int i = 0; i < outFileIndex; i++)
    // {
    //     (OutFiles[i])->close();
    //     delete OutFiles[i];
    // }
    // MapFile.close();
    mapFile.close();
    for (int i = 0; i < outFileIndex; i++)
    {
        delete funcOutFiles[i];
        delete instOutFiles[i];
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool records the read and write instructions executed" << endl;
    cerr << endl
         << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv))
        return Usage();

    mapFile.open("out.map");
    // OutFile.open(KnobOutputFile.Value().c_str());
    // MapFile.open("out.map");

    // Register Instruction to be called to instrument instructions
    // INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(Image, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    // PIN_StartProgramProbed();

    return 0;
}
