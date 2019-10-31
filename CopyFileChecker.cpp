#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace ento;

namespace {
class CopyFileChecker: public Checker <check::PostStmt<CallExpr>>{
   mutable std::unique_ptr<BuiltinBug> BT;
   void reportBug(std::string EName, unsigned ELine, const Expr *E, CheckerContext &C) const;
 
 public:
   void checkPostStmt(const CallExpr *CE, CheckerContext &C) const;
 };
}

// check function call arguments for FILE object init value
void CopyFileChecker::checkPostStmt(const CallExpr *CE,
                                   CheckerContext &C) const {
    unsigned NumArgs = CE->getNumArgs();
    if (NumArgs == 0) 
        return;
    
    for(unsigned i=0; i<NumArgs; i++) {
        const Expr *E = CE->getArg(i);
        if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(E)) {
            if (const DeclRefExpr *REF = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
                if (REF->getType().getAsString() == "FILE") {
                    if (const VarDecl *VD = dyn_cast<VarDecl>(REF->getDecl())) {
                        if (const Expr *E = VD->getInit()) {
                            // check c code
                            if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(E)) {
                                if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(ICE->getSubExpr())) {
                                    if (const ImplicitCastExpr *ICE_UO = dyn_cast<ImplicitCastExpr>(UO->getSubExpr())) {
                                        if (const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(ICE_UO->getSubExpr())) {
                                            if (DRE->getExprLoc().isMacroID()) {
                                                StringRef MacroName = Lexer::getImmediateMacroName(
                                                        DRE->getExprLoc(), C.getAnalysisManager().getSourceManager(), 
                                                        C.getAnalysisManager().getASTContext().getLangOpts());
                                                if (MacroName == "stdout") {
                                                    reportBug(REF->getNameInfo().getAsString(), 
                                                            C.getSourceManager().getSpellingLineNumber(DRE->getExprLoc()), 
                                                                DRE, C);
                                                }
                                            }
                                        }
                                    }
                                }
                            }   
                            // check c++ code
                            if (const CXXConstructExpr *CCE = dyn_cast<CXXConstructExpr>(E)) {
                                for (const Stmt *S : CCE->children()) {
                                    if (const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(S)) {
                                        if (const UnaryOperator *UO = dyn_cast<UnaryOperator>(ICE->getSubExpr())) {
                                            if (const ImplicitCastExpr *ICE_UO = dyn_cast<ImplicitCastExpr>(UO->getSubExpr())) {
                                                if (const DeclRefExpr *DRE= dyn_cast<DeclRefExpr>(ICE_UO->getSubExpr())) {
                                                    if (DRE->getExprLoc().isMacroID()) {
                                                        StringRef MacroName = Lexer::getImmediateMacroName(
                                                                DRE->getExprLoc(), C.getAnalysisManager().getSourceManager(), 
                                                                C.getAnalysisManager().getASTContext().getLangOpts());
                                                        if (MacroName == "stdout") {
                                                            reportBug(REF->getNameInfo().getAsString(), 
                                                                    C.getSourceManager().getSpellingLineNumber(DRE->getExprLoc()), 
                                                                        DRE, C);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }   
                            }
                        }
                    }
                }
            }
        }
    }
}

void CopyFileChecker::reportBug(std::string EName, unsigned ELine, const Expr *E, CheckerContext &C) const {
    std::string Msg = "Variable " + EName + " is copied FILE object, in line " + std::to_string(ELine);
    if (ExplodedNode *N = C.generateNonFatalErrorNode()) {
        if (!BT)
            BT.reset(new BuiltinBug(this, "copy a FILE object", 
                        Msg.c_str()));
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
