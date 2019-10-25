#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

#include "clang/Lex/Lexer.h"
#include "clang/AST/Expr.h"

#include <string>

using namespace clang;
using namespace ento;

namespace {
class CopyFileChecker: public Checker <check::PreStmt<DeclStmt>,
                                      check::PreCall,
                                      //check::BranchCondition>{
                                      check::PostStmt<CallExpr>>{
   mutable std::unique_ptr<BuiltinBug> BT;
   void reportBug(const Expr *E, CheckerContext &C) const;
   void reportBug(const char *Msg, const Expr *E, CheckerContext &C) const;
   void reportBug(SVal S, const Expr *E, CheckerContext &C) const;
 
 public:
   void checkPreStmt(const DeclStmt *DS, CheckerContext &C) const;
   void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;
   //void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
   void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

 };
}

void CopyFileChecker::checkPreStmt(const DeclStmt *DS,
                                   CheckerContext &C) const {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        //if (VD->getType().getAsString() != "FILE")
          //  return;
        if (const Expr *E = VD->getInit()) {
            // check for c code
            if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(E)) {
                if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(ICE->getSubExpr())) {
                    if (const ImplicitCastExpr *ICE_UO = dyn_cast<ImplicitCastExpr>(UO->getSubExpr())) {
                        if (const DeclRefExpr *REF = dyn_cast<DeclRefExpr>(ICE_UO->getSubExpr())) {
                            if (REF->getExprLoc().isMacroID()) {
                                StringRef MacroName = Lexer::getImmediateMacroName(
                                        REF->getExprLoc(), C.getAnalysisManager().getSourceManager(), 
                                        C.getAnalysisManager().getASTContext().getLangOpts());
                                if (MacroName == "stdout") {
                                    //reportBug(REF, C);
                                }
                            }
                        }
                    }
                }
            }
            //check for c++ code
            /*if (const CXXConstructExpr *CCE = dyn_cast<CXXConstructExpr>(E)) {
                if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(CCE->getArgs())) {
                    if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(ICE->getSubExpr())) {
                        if (const ImplicitCastExpr *ICE_UO = dyn_cast<ImplicitCastExpr>(UO->getSubExpr())) {
                            if (const DeclRefExpr *REF = dyn_cast<DeclRefExpr>(ICE_UO->getSubExpr())) {
                                if (REF->getExprLoc().isMacroID()) {
                                    StringRef MacroName = Lexer::getImmediateMacroName(
                                            REF->getExprLoc(), C.getAnalysisManager().getSourceManager(), 
                                            C.getAnalysisManager().getASTContext().getLangOpts());
                                    if (MacroName == "stdout") {
                                        reportBug(REF, C);
                                    }
                                }
                            }
                        }
                    }
                }
            }*/
        }
    }
}

void CopyFileChecker::checkPostStmt(const CallExpr *CE,
                                   CheckerContext &C) const {
    unsigned NumArgs = CE->getNumArgs();
    if (NumArgs == 0) 
        return;
    
    for(unsigned i=0; i<NumArgs; i++) {
        const Expr *E = CE->getArg(i);
        if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
            if (const DeclRefExpr *REF = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
                reportBug(REF->getNameInfo().getAsString().c_str(),REF, C);
            }
        }
    }
}

void CopyFileChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    /*for (const ParmVarDecl *Param : Call.parameters()) {
        std::string ParamTypeStr = Param->getType().getAsString();
        //reportBug(ParamTypeStr.c_str(), Call.getOriginExpr(), C);
        reportBug(ParamTypeStr.c_str(), Param->getDefaultArg(), C);
        if(ParamTypeStr == "const struct __sFILE &") {
            ProgramStateRef State = C.getState();
        }
    }*/
}


void CopyFileChecker::reportBug(const Expr *E, CheckerContext &C) const {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        if (!BT)
            BT.reset(new BuiltinBug(this, "copy a FILE object",
                        "Do not copy a FILE object"));
            auto R = llvm::make_unique<BugReport>(*BT, BT->getDescription(), N);
            R->addRange(E->getSourceRange());
            C.emitReport(std::move(R));
    }
}

void CopyFileChecker::reportBug(const char *Msg, const Expr *E, CheckerContext &C) const {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        if (!BT)
            BT.reset(new BuiltinBug(this, "copy a FILE object", 
                        Msg));
                        //"Do not copy a FILE object"));
            auto R = llvm::make_unique<BugReport>(*BT, BT->getDescription(), N);
            R->addRange(E->getSourceRange());
            C.emitReport(std::move(R));
    }
}


void CopyFileChecker::reportBug(SVal S, const Expr *E, CheckerContext &C) const {
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        if (!BT)
            BT.reset(new BuiltinBug(this, "copy a FILE object", 
                        "Do not copy a FILE object"));
            auto R = llvm::make_unique<BugReport>(*BT, BT->getDescription(), N);
            R->addRange(E->getSourceRange());
            R->markInteresting(S);
            C.emitReport(std::move(R));
    }
}

void ento::registerCopyFileChecker(CheckerManager &mgr) {
    mgr.registerChecker<CopyFileChecker>();
}

bool ento::shouldRegisterCopyFileChecker(const LangOptions &LO) {
    return true;
}

