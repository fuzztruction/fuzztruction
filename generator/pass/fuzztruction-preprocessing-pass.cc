#include "fuzztruction-preprocessing-pass.hpp"

/*
Split a string containing multiple comma-separated keywords
and return the set of these keywords
*/
static std::vector<std::string> split_string(std::string s, char delim) {
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
Replace functions related to batch memory operations like memcpy or
memmove with a custom, instrumentable implementation. These custom_*
function are implemented in a object file that is linked into by the
compiler wrapper.
*/
// as of now, parseIRFile files (destructor of IM finds uses without def)
bool FuzztructionSourcePreprocesssingPass::replaceMemFunctions(Module &M) {
    bool modified = false;

    dbgs() << "FT DEBUG: Module name " << M.getName() << "\n";
    // cannot replace functions in the module we load the replacements from
    if (M.getName() == "mem_functions.c")
        return modified;

    SMDiagnostic sm;
    // FIXME: this path should not be absolute.
    std::unique_ptr<Module> IM = parseIRFile("/home/user/fuzztruction/generator/pass/mem_functions.ll", sm, M.getContext());
    dbgs() << "FT DEBUG: mem_functions.ll IR file parsed\n";
    if (!IM) {
        errs() << "FT ERROR: ";
        sm.print("Error diagnostics from parsing mem_functions.ll file", errs());
        abort();
    }
    // import all functions we want to replace
    for (auto &F : *IM) {
        // skip functions that are only declared
        if (F.isDeclaration())
            continue;
        std::string new_name = F.getName().str();
        // check if we need to import the function (has it any uses?)
        // We assume that all functions are in format custom_NAME.
        std::string orig_name = split_string(new_name, '_').back();
        Function *orig_f = M.getFunction(orig_name);
        if (!orig_f) {
            dbgs() << "FT DEBUG: " << orig_name << " not used in " << M.getName() << "\n";
            continue;
        }
        dbgs() << "FT DEBUG: Importing " << new_name << "\n";
        // create new function into which we will clone F
        auto NewF = Function::Create(F.getFunctionType(), F.getLinkage(), new_name, M);
        NewF->setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
        NewF->addFnAttr(Attribute::AlwaysInline);

        // Loop over the arguments, copying the names of the mapped arguments over...
        ValueToValueMapTy VMap;
        Function::arg_iterator DestI = NewF->arg_begin();
        for (const Argument & I : F.args())
            if (VMap.count(&I) == 0) {     // Is this argument preserved?
                dbgs() << "FT DEBUG: arg=" << I.getName() << "\n";
                DestI->setName(I.getName()); // Copy the name over...
                VMap[&I] = &*DestI++;        // Add mapping to VMap
        }

        dbgs() << "FT DEBUG: Cloning " << new_name << "\n";
        // TODO: we assume at most 8 return leafs?
        SmallVector<ReturnInst*, 8> Returns;
        CloneFunctionInto(NewF, &F, VMap, false, Returns);
        modified = true;

        // Once we imported our replacement, we can use it to actually replace functions
        dbgs() << "FT DEBUG: Replacing " << orig_f->getName().str() << " by " << new_name << "\n";
        // orig_f->replaceAllUsesWith(NewF);
        for (auto user : orig_f->users()) {
            if (CallInst* call_ins = dyn_cast<CallInst>(user)){
                // TODO: can we simply setCalledFunction?
                // call_ins->setCalledFunction(NewF);
                std::vector<Value *> args (call_ins->args().begin(), call_ins->args().end());
                IRBuilder<> ins_builder(call_ins->getNextNode());
                auto *new_call = ins_builder.CreateCall(NewF, args);
                call_ins->replaceAllUsesWith(new_call);
                call_ins->eraseFromParent();
            }
        }
        orig_f->eraseFromParent();
    };
    dbgs() << "FT DEBUG: Done\n";

    return modified;
}

bool FuzztructionSourcePreprocesssingPass::runOnModule(Module &M) {
    dbgs() << "Running FuzztructionSourcePreprocesssingPass\n";
    bool module_modified = false;
    module_modified |= replaceMemFunctions(M);

    return module_modified;
}
