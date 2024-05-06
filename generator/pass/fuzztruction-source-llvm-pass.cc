#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "llvm/IR/Instruction.h"
#include "llvm/IR/GlobalValue.h"

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

#include "llvm/IR/Intrinsics.h"

#include "llvm/Transforms/Utils.h"
#include <cstdio>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Attributes.h>

#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IRReader/IRReader.h>

#include <cstdint>
#include <cstdlib>

#include <random>
#include <utility>
#include <vector>

#include "config.hpp"

#include "fuzztruction-preprocessing-pass.hpp"

using namespace llvm;

/*
We need the following capabilites:
    - The ability to mutate the values loaded/stored by load and store instructions.
    - Some way to trace which store/load instructions where executed in which order.
        - via. INT3 tracing?
        - via. patch point and custom stub that is called?
        - ?We need some RT to transfer the traces to the parent
*/

namespace {

    class FuzztructionSourcePass : public ModulePass {

    public:

        static char ID;
        static bool allow_ptr_ty;
        static bool allow_vec_ty;
        FuzztructionSourcePass() : ModulePass(ID) { }

        enum InsTy {Random = 0, Load = 1, Store = 2, Add = 3, Sub = 4, Icmp = 5, Select = 6, Branch = 7, Switch = 8};
        static std::string insTyNames[9];

        bool initializeFuzzingStub(Module &M);
        bool injectPatchPoints(Module &M);
        std::vector<Value *> getPatchpointArgs(Module &M, uint32_t id);
        bool instrumentInsArg(Module &M, Function *stackmap_intr, Instruction *ins, uint8_t op_idx);
        bool instrumentInsOutput(Module &M, Function *stackmap_intr, Instruction *ins);
        bool maybeDeleteFunctionCall(Module &M, CallInst *call_ins, std::set<std::string> &target_functions);
        bool filterInvalidPatchPoints(Module &M);
        bool replaceMemFunctions(Module &M);

        bool runOnModule(Module &M) override;

        StringRef getPassName() const override {
            return "FuzzTruction Source Pass";
        }

    };


}

/*
Specify instruction types, which we want to instrument with probability p
*/
struct InsHook {
    FuzztructionSourcePass::InsTy type;
    uint8_t probability;

    std::string to_string() {
        return "InsHook{ ins_ty=" + FuzztructionSourcePass::insTyNames[type] +
                ", probability=" + std::to_string(probability) + "% }";
    }
};

inline bool operator<(const InsHook& lhs, const InsHook& rhs)
{
  return lhs.type < rhs.type;
}


bool FuzztructionSourcePass::runOnModule(Module &M) {

    bool module_modified = false;

    module_modified |= initializeFuzzingStub(M);
    module_modified |= injectPatchPoints(M);
    module_modified |= filterInvalidPatchPoints(M);

    return module_modified;
}


/*
Split a string containing multiple comma-separated keywords
and return the set of these keywords
*/
std::vector<std::string> split_string(std::string s, char delim) {
    size_t pos_start = 0, pos_end;
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find (delim, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + 1;
        res.push_back(token);
    }

    res.push_back(s.substr (pos_start));
    return res;
}

/*
Check if an environment variable is set.
*/
bool env_var_set(const char* env_var) {
    const char* envp = std::getenv(env_var);
    if (envp)
        return true;
    return false;
}


/*
Convert environment variable content to a set.
Expects comma-separated list of values in the env var.
*/
std::vector<std::string> parse_env_var_list(const char* env_var) {
    const char* envp = std::getenv(env_var);
    if (!envp)
        return std::vector<std::string> ();
    return split_string(std::string(envp), /* delim = */ ',');
}


/*
Extract integer specified in environment variable.
*/
uint32_t parse_env_var_int(const char* env_var, uint32_t default_val) {
    const char* envp = std::getenv(env_var);
    if (!envp)
        return default_val;
    uint32_t val = (uint32_t)std::stol(envp);
    return val;
}


/*
Convert set of strings to known instruction types. Ignores unknown elements.
*/
FuzztructionSourcePass::InsTy to_InsTy(std::string input) {
    // dbgs() << "val=" << val << "\n";
    if (input == "random")
        return FuzztructionSourcePass::InsTy::Random;
    if (input == "load")
        return FuzztructionSourcePass::InsTy::Load;
    if (input == "store")
        return FuzztructionSourcePass::InsTy::Store;
    if (input == "add")
        return FuzztructionSourcePass::InsTy::Add;
    if (input == "sub")
        return FuzztructionSourcePass::InsTy::Sub;
    if (input == "icmp")
        return FuzztructionSourcePass::InsTy::Icmp;
    if (input == "select")
        return FuzztructionSourcePass::InsTy::Select;
    if (input == "branch")
        return FuzztructionSourcePass::InsTy::Branch;
    if (input == "switch")
        return FuzztructionSourcePass::InsTy::Switch;

    errs() << "Unsupported instruction string received: " << input << "\n";
    exit(1);
}


/*
Convert a string of format "name:probability" to InsHook struct.
*/
InsHook to_InsHook(std::string s) {
    int pos = s.find_first_of(':');
    if (pos == std::string::npos)
        return {to_InsTy(s), 100};
    std::string name = s.substr(0, pos);
    uint32_t prob = std::stol(s.substr(pos + 1));
    assert(prob <= 100 && "Probability must be in range [0, 100]");
    return {to_InsTy(name), (uint8_t)prob};
}


bool FuzztructionSourcePass::initializeFuzzingStub(Module &M) {
    /*
    Used to initialize our fuzzing stub. We can not use the llvm constructor attribute because
    our stub relies on keystone which has static constructors that are executed after functions
    marked by the constructor attribute. Hence, we can not use keystone at that point in time.
    */
    auto hook_fn = M.getOrInsertFunction("__ft_auto_init", FunctionType::getVoidTy(M.getContext()));
    auto main_fn = M.getFunction("main");
    if (main_fn) {
        IRBuilder<> ins_builder(main_fn->getEntryBlock().getFirstNonPHI());
        ins_builder.CreateCall(hook_fn);
    }

    return true;
}


/*
Delete call if one of the functions specified by name is called
*/
bool FuzztructionSourcePass::maybeDeleteFunctionCall(Module &M, CallInst *call_ins, std::set<std::string> &target_functions) {
    Function *callee = call_ins->getCalledFunction();
    // skip indirect calls
    if (!callee) {
        return false;
    }
    // if called function should be deleted, erase it from IR
    if (target_functions.count(callee->getName().str())) {
        // if the callee expects a ret value, we cannot simply replace the function
        // TODO: we could determine type and replace Inst with Value
        if (!call_ins->getCalledFunction()->getReturnType()->isVoidTy()) {
            errs() << "Cannot delete " << callee->getName() << " as it returns\n";
            return false;
        }
        dbgs() << "deleteFunctionCalls(): Deleting call to " << callee->getName() << "\n";
        call_ins->eraseFromParent();
        return true;
    }
    return false;
}


/*
Get vector of default patchpoint arguments we need for every patchpoint.
ID is set depending on which type of instruction is instrumented.
*/
std::vector<Value *> FuzztructionSourcePass::getPatchpointArgs(Module &M, uint32_t id) {
    IntegerType *i64_type = IntegerType::getInt64Ty(M.getContext());
    IntegerType *i32_type = IntegerType::getInt32Ty(M.getContext());
    IntegerType *i8_type = IntegerType::getInt8Ty(M.getContext());

    std::vector<Value *> patchpoint_args;

    /* The ID of this patch point */
    Constant *c = ConstantInt::get(i64_type, id);
    // Constant *id = ConstantInt::get(i64_type, 0xcafebabe);
    patchpoint_args.push_back(c);

    /* Set the shadown length in bytes */
    Constant *shadow_len = ConstantInt::get(i32_type, FT_PATCH_POINT_SIZE);
    patchpoint_args.push_back(shadow_len);

    /*The function we are calling */
    auto null_ptr = ConstantPointerNull::get(PointerType::get(i8_type, 0));
    //Constant *fnptr = ConstantInt::get(i32_type, 1);
    //auto null_ptr = ConstantExpr::getIntToPtr(fnptr, PointerType::get(i8_type, 0));
    patchpoint_args.push_back(null_ptr);

    /*
    The number of args that should be considered as function arguments.
    Reaming arguments are the live values for which the location will be
    recorded.
     */
    Constant *argcnt = ConstantInt::get(i32_type, 0);
    patchpoint_args.push_back(argcnt);

    return patchpoint_args;
}


/*
Instrument the output value of the instruction. In other words, the value produced by the instruction
is the live value fed into the patchpoint.
*/
bool FuzztructionSourcePass::instrumentInsOutput(Module &M, Function *stackmap_intr, Instruction *ins) {
    // dbgs() << "instrumentInsOutput called\n";
    Instruction *next_ins = ins;
    /* In case of a load the patchpoint is inserted after the load was executed */
    if (ins)
        next_ins = ins->getNextNode();
    if (!next_ins)
        return false;

    IRBuilder<> ins_builder(next_ins);

    /*
        declare void
        @llvm.experimental.patchpoint.void(i64 <id>, i32 <numBytes>,
                                            i8* <target>, i32 <numArgs>, ...)
    */
    std::vector<Value *> patchpoint_args = getPatchpointArgs(M, ins->getOpcode());

    patchpoint_args.push_back(ins);
    ins_builder.CreateCall(stackmap_intr, patchpoint_args);

    return true;
}


/*
Instrument (one of) the input value(s) to the instruction (as specified by operand index).
This input value is the live value connected to the patchpoint, where it can be modified before being
processed by the instruction.
*/
bool FuzztructionSourcePass::instrumentInsArg(Module &M, Function *stackmap_intr, Instruction *ins, uint8_t op_idx) {
    // dbgs() << "instrumentInsArg called\n";
    if (!ins)
        return false;

    IRBuilder<> ins_builder(ins);

    /*
        declare void
        @llvm.experimental.patchpoint.void(i64 <id>, i32 <numBytes>,
                                            i8* <target>, i32 <numArgs>, ...)
    */
    std::vector<Value *> patchpoint_args = getPatchpointArgs(M, ins->getOpcode());

    /* We want to modify argument at op_idx (e.g., 0 for stores) */
    patchpoint_args.push_back(ins->getOperand(op_idx));
    ins_builder.CreateCall(stackmap_intr, patchpoint_args);

    return true;
}


bool isValidTy(Type* ty) {
    if (ty->isIntegerTy())
        return true;
    if (FuzztructionSourcePass::allow_ptr_ty && ty->isPointerTy())
        return true;
    if (FuzztructionSourcePass::allow_vec_ty && ty->isVectorTy())
        return true;
    return false;
}

/*
Check whether it is reasonable to instrument the given instruction.
Ensure that
1) at least one user exists (else the value will never be used)
2) we support the type (integer, vec, and ptr types currently)
3) we exclude "weird" instructions (e.g., debug instructions, phi nodes etc)
*/
bool canBeInstrumented(Instruction *ins) {
    // ignore instructions that are never used
    if (ins->users().begin() == ins->users().end())
        return false;
    // ignore non-integer type instructions
    if (!isValidTy(ins->getType()))
        return false;
    if (ins->isKnownSentinel())
        return false;
    if (ins->isCast())
        return false;
    // if (ins->isDebugOrPseudoInst())
    //     return false;
    if (ins->isExceptionalTerminator())
        return false;
    if (ins->isLifetimeStartOrEnd())
        return false;
    if (ins->isEHPad())
        return false;
    if (ins->isFenceLike())
        return false;
    if (ins->isSwiftError())
        return false;
    if (ins->getOpcode() == Instruction::PHI)
        return false;
    return true;
}


/*
Instrument all instructions and delete function calls specified by the user via environment variables.

User can specify instruction types ("load", "store"), for which we want to insert a patchpoint
as well as function names ("abort"), for which we erase any call to (if possible).
Function names are specified in FT_NOP_FN=abort,_bfd_abort.

Instruction types are specified in FT_HOOK_INS=store:50,load,add
Format is 'instruction_name':'probability of selecting a specific instance'.
Instruction name must be one of the following: add, sub, store, load, random

The value random is special in the sense that each instruction we can instrument, is actually instrumented.
We recommend to set a probability, at least for random (to avoid instrumenting too many instructions).
*/
bool FuzztructionSourcePass::injectPatchPoints(Module &M) {
    /* Get the patchpoint intrinsic */
    Function* stackmap_intr = Intrinsic::getDeclaration(&M,
        Intrinsic::experimental_patchpoint_void
    );
    stackmap_intr->setCallingConv(CallingConv::AnyReg);

    auto allowlisted_files = parse_env_var_list("FT_FILE_ALLOWLIST");
    dbgs() << "allowlisted_files: " << allowlisted_files.size() << "\n";

    auto blocklisted_files = parse_env_var_list("FT_FILE_BLOCKLIST");
    dbgs() << "blocklisted_files: " << blocklisted_files.size() << "\n";

    if (allowlisted_files.size() > 0) {
        if (std::find(allowlisted_files.begin(), allowlisted_files.end(), M.getSourceFileName()) != allowlisted_files.end()) {
            dbgs() << "FT: File is listed as allowed " << M.getSourceFileName() << "\n";
        } else {
            dbgs() << "FT: File is not on the allow list " << M.getSourceFileName() << "\n";
            return false;
        }
    } else {
        if (std::find(blocklisted_files.begin(), blocklisted_files.end(), M.getSourceFileName()) != blocklisted_files.end()) {
            dbgs() << "FT: Skipping blockedlisted file " << M.getSourceFileName() << "\n";
            return false;
        }
    }

    FuzztructionSourcePass::allow_ptr_ty = !env_var_set("FT_NO_PTR_TY");
    FuzztructionSourcePass::allow_vec_ty = !env_var_set("FT_NO_VEC_TY");

    // Get functions which should not be called (i.e., for which we delete calls to)
    auto fn_del_vec = parse_env_var_list("FT_NOP_FN");
    std::set<std::string> fn_del (fn_del_vec.begin(), fn_del_vec.end());
    dbgs() << "FT: Deleting function calls to " << fn_del.size() << " functions\n";

    // Get instruction types we want to instrument
    std::set<InsHook> hook_ins = {};
    for (std::string e : parse_env_var_list("FT_HOOK_INS")) {
        dbgs() << "FT DEBUG: parsed ins_hook: " << to_InsHook(e).to_string() << "\n";
        hook_ins.insert(to_InsHook(e));
    }
    dbgs() << "FT: Instrumenting " << hook_ins.size() << " types of instructions\n";
    if (!hook_ins.size()) {
        errs() << "FT: FT_HOOK_INS is not set\n";
    }

    // use random number from hardware to seed mersenne twister prng
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, 100); // inclusive [0, 100]

    // Track whether we modified the module
    bool modified = false;
    uint64_t num_patchpoints = 0;
    for (auto &F : M) {
        for (auto &B : F) {
            for (BasicBlock::iterator DI = B.begin(); DI != B.end(); ) {
                // ensure that iterator points to next instruction
                // in case we need to delete the instruction
                Instruction& I = *DI++;

                if (auto *call_ins = dyn_cast<CallInst>(&I)) {
                    bool deleted = maybeDeleteFunctionCall(M, call_ins, fn_del);
                    modified |= deleted;
                    // No point to continue if we just deleted the instruction
                    if (deleted)
                        continue;
                }

                // Check if the current instruction is hooked.
                for (const auto& ins_hook : hook_ins) {
                    bool ins_modified = false;
                    switch (ins_hook.type) {
                        case FuzztructionSourcePass::InsTy::Load:
                            if (auto *load_op = dyn_cast<LoadInst>(&I)) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsOutput(M, stackmap_intr, &I);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Store:
                            if (auto *store_op = dyn_cast<StoreInst>(&I)) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Add:
                            if (I.getOpcode() == Instruction::Add) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Sub:
                            if (I.getOpcode() == Instruction::Sub) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 1);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Icmp:
                            if (I.getOpcode() == Instruction::ICmp) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsOutput(M, stackmap_intr, &I);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Select:
                            if (I.getOpcode() == Instruction::Select) {
                                if (distr(gen) <= ins_hook.probability)
                                    // Arg 0 is the selection mask
                                    ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Branch:
                            // FIXME: Fails to compile.
                            // if (I.getOpcode() == Instruction::Br && distr(gen) <= ins_hook.probability) {
                            //     // Arg 0 is the branch condition (i1)
                            //     ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 0);
                            // }
                            break;
                        case FuzztructionSourcePass::InsTy::Switch:
                            if (I.getOpcode() == Instruction::Switch && distr(gen) <= ins_hook.probability) {
                                // Arg 0 is the switch condition (i1)
                                ins_modified = instrumentInsArg(M, stackmap_intr, &I, /* op_idx = */ 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Random:
                            if (!canBeInstrumented(&I))
                                break;
                            if (distr(gen) <= ins_hook.probability) {
                                ins_modified = instrumentInsOutput(M, stackmap_intr, &I);
                            }
                    }
                    if (ins_modified) {
                        modified = true;
                        num_patchpoints++;
                        // instruction cannot have multiple types
                        // no point in trying other types if we just matched
                        break;
                    }
                }
            }
        }
        //llvm::errs() << "dump-start\n";
        //F.dump();
    }
    dbgs() << "FT: Inserted " << num_patchpoints << " patchpoints\n";

    return modified;
}

/*
Filter & delete patchpoints if the live value is already used
by another patchpoint.
*/
bool FuzztructionSourcePass::filterInvalidPatchPoints(Module &M) {
    bool modified = false;
    Function* stackmap_intr = Intrinsic::getDeclaration(&M,
        Intrinsic::experimental_patchpoint_void
    );
    stackmap_intr->setCallingConv(CallingConv::AnyReg);

    int num_users = 0;
    dbgs() << "FT: Filtering invalid patch points\n";
    std::set<Value *> used_values = {};
    std::set<Instruction *> pending_deletions = {};
    for (const auto& user : stackmap_intr->users()) {
        num_users++;
        if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
            //errs() << "is sen: " << call_ins->isKnownSentinel() << "\n";
            for (unsigned i = 4; i < call_ins->getNumArgOperands(); ++i) {
                //errs() << "call ins\n";
                //dbgs() << "call ins on dbg\n";
                //call_ins->dump();
                //errs().flush();
                Value *val = call_ins->getArgOperand(i);
                //errs() << "val\n";
                //val->dump();
                if (used_values.count(val) > 0) {
                    pending_deletions.insert(call_ins);
                    break;
                } else {
                    used_values.insert(val);
                }
            }
        }
    }
    for (auto &ins : pending_deletions) {
        //assert(ins->isSafeToRemove() && "Instruction is not safe to remove!");
        assert((ins->users().end() == ins->users().begin()) && "Cannot delete call instruction as it has uses");
        modified = true;
        ins->eraseFromParent();
    }
    dbgs() << "FT: Deleted " << pending_deletions.size() << "/" << num_users;
    dbgs() << " patchpoints as live values were already recorded\n";
    return modified;
}


char FuzztructionSourcePass::ID = 0;
bool FuzztructionSourcePass::allow_ptr_ty = false;
bool FuzztructionSourcePass::allow_vec_ty = false;
std::string FuzztructionSourcePass::insTyNames[] = {"random", "load", "store", "add", "sub", "icmp", "select", "br", "switch"};

static void registerSourcePass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {
    if (!env_var_set("FT_DISABLE_INLINEING")) {
        PM.add(new FuzztructionSourcePreprocesssingPass());
        PM.add(llvm::createAlwaysInlinerLegacyPass());
    }
    PM.add(new FuzztructionSourcePass());
}

static RegisterStandardPasses RegisterSourcePass(
    PassManagerBuilder::EP_OptimizerLast, registerSourcePass);

static RegisterStandardPasses RegisterSourcePass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerSourcePass);
