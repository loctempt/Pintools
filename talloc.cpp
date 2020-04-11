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

ofstream mapFile;
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
VOID recordWriteIns(ADDRINT ptr, UINT32 size, int fileIdx)
{
    printTimestamp(instOutFiles[fileIdx]);
    (*(instOutFiles[fileIdx])) << hex << showbase
                               << "w @ " << ptr << " " << size << endl;
}

VOID recordReadIns(ADDRINT ptr, UINT32 size, int fileIdx)
{
    printTimestamp(instOutFiles[fileIdx]);
    (*(instOutFiles[fileIdx])) << hex << showbase
                               << "r @ " << ptr << " " << size << endl;
}

VOID printIns(ADDRINT val, int fileIdx)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << "returns: " << val << endl;
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
                               << name << "(" << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

VOID CallocBefore(CHAR *name, int fileIdx, ADDRINT returnAddr, ADDRINT nmemb, ADDRINT size)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << name << "(" << nmemb << ", " << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

VOID ReallocBefore(CHAR *name, int fileIdx, ADDRINT returnAddr, ADDRINT ptr, ADDRINT size)
{
    printTimestamp(funcOutFiles[fileIdx]);
    (*(funcOutFiles[fileIdx])) << hex << showbase
                               << name << "(" << ptr << ", " << size << ")"
                               << endl;
    returnAddress = returnAddr;
}

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
    // Insert a call at function return point, getting
    // the function's return value by reading EAX/RAX.
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
                       IARG_MEMORYREAD_SIZE,
                       IARG_UINT32, fileIdx,
                       IARG_END);
    }
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordWriteIns,
                       IARG_MEMORYWRITE_EA,
                       IARG_MEMORYWRITE_SIZE,
                       IARG_UINT32, fileIdx,
                       IARG_END);
    }
}

VOID instFunc(IMG &img, SYM &sym, string &funcName)
{
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

    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        string undecorateFuncName = PIN_UndecorateSymbolName(SYM_Name(sym),
                                                             UNDECORATION_NAME_ONLY);
        instFunc(img, sym, undecorateFuncName);
    }
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
                            "o", "rwcount.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
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

    // Register Instruction to be called to instrument instructions
    IMG_AddInstrumentFunction(Image, 0);

    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    // PIN_StartProgramProbed();

    return 0;
}
