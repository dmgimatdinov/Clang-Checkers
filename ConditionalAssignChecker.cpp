//#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/ASTImporter.h"
//#include "clang/Analysis/AnalysisContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/BugReporter/PathDiagnostic.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"

#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"
#include "string"

using namespace clang;
using namespace ento;

namespace {

class WalkAST : public StmtVisitor<WalkAST> {
  BugReporter &BR;
  AnalysisDeclContext* AC;
  const CheckerBase* CB;
  
public :
  WalkAST (BugReporter &br, AnalysisDeclContext *ac, const CheckerBase *cb)
	: BR(br), AC(ac), CB(cb) {}
  
  // Statement visitor methods
  void VisitStmt(Stmt *S) { VisitChildren(S); };
  void VisitIfStmt(IfStmt *IS);
  void VisitForStmt(ForStmt *FS);
  void VisitWhileStmt(WhileStmt *WS);
  void VisitDoStmt(DoStmt *DS);

  void VisitAbstractConditionalOperator(AbstractConditionalOperator *ACO);
  void VisitBinaryOperator(BinaryOperator *BO);

  void VisitChildren(Stmt *S);

  // Checker-specific methods
  void checkConditionForAssign(const Expr *condition);

  // Helpers
  void reportBug(const Stmt *S);
  void reportBugPtr(const Stmt *S);
  // void printExpr(Expr *E);
};
}

void WalkAST::VisitChildren(Stmt *S) {
  for(Stmt *Child : S->children())
    if(Child)
      Visit(Child);
}

// check statements
void WalkAST::VisitIfStmt(IfStmt *IS) {
  checkConditionForAssign(IS->getCond());

  // Recurse and check children
  VisitChildren(IS);
}
void WalkAST::VisitForStmt(ForStmt *FS) {
  checkConditionForAssign(FS->getCond());
  VisitChildren(FS);
}

void WalkAST::VisitWhileStmt(WhileStmt *WS) {
  checkConditionForAssign(WS->getCond());
  VisitChildren(WS);
}

void WalkAST::VisitDoStmt(DoStmt *DS) {
  checkConditionForAssign(DS->getCond());
  VisitChildren(DS);
}

// check condition for ternarny operator
void WalkAST::VisitAbstractConditionalOperator(AbstractConditionalOperator *ACO) {
  if(OpaqueValueExpr *OVL = dyn_cast<OpaqueValueExpr>(ACO->getCond())) {
    checkConditionForAssign(OVL->getSourceExpr()->IgnoreParenCasts());
    VisitChildren(ACO);
    return;
  }
  checkConditionForAssign(ACO->getCond()->IgnoreParenCasts());
  VisitChildren(ACO);
}
  
// check && and || operators
void WalkAST::VisitBinaryOperator(BinaryOperator *BO) {
  if(BO->isLogicalOp()) {
    checkConditionForAssign(BO->getLHS()->IgnoreParenCasts()); 
    checkConditionForAssign(BO->getRHS()->IgnoreParenCasts()); 
  }
  VisitChildren(BO);
}

// Checker-specific methods
void WalkAST::checkConditionForAssign(const Expr *condition) {
  if(!condition) {
    return;  
  }

  if(dyn_cast<ParenExpr> (condition)) {
    return;
  }

  // check for function
  if(dyn_cast<CallExpr> (condition)) {
    return;
  }
  
  // check ternarny operator inside condition   
  if(const AbstractConditionalOperator *ACO = dyn_cast<AbstractConditionalOperator> (condition)) {
    Expr *TE = ACO->getTrueExpr()->IgnoreParenCasts();
    Expr *FE = ACO->getFalseExpr()->IgnoreParenCasts();

    if(const BinaryOperator *BTE = dyn_cast<BinaryOperator>(TE)) {
      if(BTE->isAssignmentOp()) {
        reportBug(BTE); 
      }
    }

    if(const BinaryOperator *BFE = dyn_cast<BinaryOperator>(FE)) {
      if(BFE->isAssignmentOp()) {
        reportBug(BFE); 
      }
    }
  }

  // check for comma operator inside condition and simple check
  if(const BinaryOperator *B = dyn_cast<BinaryOperator>(condition)) {
    if(B->getOpcodeStr() == ",") {
      if(const BinaryOperator *BRHS = dyn_cast<BinaryOperator>(B->getRHS())) {
        if(BRHS->isEqualityOp() || BRHS->isComparisonOp()) {
          return;
        }

        if(BRHS->isAssignmentOp()) {
          reportBug(BRHS);
        }
      }
      return;
    }
    
    // simple check
    if(B->isAssignmentOp()) {
      // check for pointers
      if(B->getLHS()->getType()->isPointerType()) {
        reportBugPtr(B);
        return;
      } 
      reportBug(B);
    }
  }
}

void WalkAST::reportBug(const Stmt *S) {
  PathDiagnosticLocation ELoc =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), AC);
  BR.EmitBasicReport(AC->getDecl(), CB,
		  "", 
		  "CONDITIONAL_ASSIGN",
		  "USING ASSIGNMENT INSTEAD OF CONDITIONAL OPERATORS", 
		  ELoc, S->getSourceRange());
}

void WalkAST::reportBugPtr(const Stmt *S) {
  PathDiagnosticLocation ELoc =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), AC);
  BR.EmitBasicReport(AC->getDecl(), CB,
		  "", 
		  "CONDITIONAL_ASSIGN.PTR",
		  "USING ASSIGNMENT INSTEAD OF CONDITIONAL OPERATORS", 
		  ELoc, S->getSourceRange());
}

/*void WalkAST::printExpr(Expr *E) {
  SourceRange range = E->getSourceRange();
  SourceManager* SM = &(AC->getASTContext().getSourceManager());
  llvm::StringRef ref = Lexer::getSourceText(CharSourceRange::getCharRange(range), *SM, LangOptions());
  std::cout << ref.str() << std::endl;
}*/

namespace {
class ConditionalAssignChecker : public Checker<check::ASTCodeBody> {
public :
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    WalkAST walker(BR, mgr.getAnalysisDeclContext(D), this);
    walker.Visit(D->getBody());
  }
};
}

void ento::registerConditionalAssignChecker(CheckerManager &mgr) {
  mgr.registerChecker<ConditionalAssignChecker>();
}

bool ento::shouldRegisterConditionalAssignChecker(const LangOptions &LO) {
   return true;
}
