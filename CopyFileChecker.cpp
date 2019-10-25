#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"

#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"

#include "clang/Lex/Lexer.h"
#include "clang/AST/Expr.h"

using namespace clang;
using namespace ento;

namespace {
class CopyFileChecker: public Checker <check::PreStmt<DeclStmt>,
                                      //check::PreCall>{
                                      //check::BranchCondition>{
                                      check::PostStmt<Expr>>{
   mutable std::unique_ptr<BuiltinBug> BT;
   void reportBug(const Expr *E, CheckerContext &C) const;
 
 public:
   void checkPreStmt(const DeclStmt *DS, CheckerContext &C) const;
   void checkPostStmt(const Expr *E, CheckerContext &C) const;
   //void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
   //void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

 };
}

void CopyFileChecker::checkPreStmt(const DeclStmt *DS,
                                   CheckerContext &C) const {
    if (const VarDecl *VD = dyn_cast<VarDecl>(DS->getSingleDecl())) {
        if (const Expr *E = VD->getInit()) {
            if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(E)) {
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
        }
    }
}

void CopyFileChecker::checkPostStmt(const Expr *E,
                                   CheckerContext &C) const {
    /*if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(E)) {
        reportBug(ICE, C);
        if (const DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(ICE->getSubExpr())) {
            if (Ref->getExprLoc().isMacroID()) {
                StringRef MacroName = Lexer::getImmediateMacroName(
                        Ref->getExprLoc(), C.getAnalysisManager().getSourceManager(), 
                        C.getAnalysisManager().getASTContext().getLangOpts());
                if (MacroName == "stdout") {
                    //reportBug(Ref, C);
                    if (const VarDecl *VD = dyn_cast<VarDecl>(Ref->getFoundDecl())) {
                        if (const Expr *IE = VD->getInit()) {
                            reportBug(IE, C);
                        }
                    }
                }
            }
        }
    }*/
}

/*void CopyFileChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    for (const ParmVarDecl *Param : Call.parameters()) {
        std::string ParamTypeStr = Param->getType().getAsString();
        if(ParamTypeStr == "const struct __sFILE &") {
            ProgramStateRef State = C.getState();
            reportBug(ParamTypeStr, State, C);
        }
    }
}*/


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

void ento::registerCopyFileChecker(CheckerManager &mgr) {
    mgr.registerChecker<CopyFileChecker>();
}

bool ento::shouldRegisterCopyFileChecker(const LangOptions &LO) {
    return true;
}

