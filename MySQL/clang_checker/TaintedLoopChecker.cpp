#include "Taint.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/ParentMap.h"

using namespace clang;
using namespace ento;
using namespace taint;

namespace {

	class TaintedLoopChecker : public Checker<check::BranchCondition> {

		mutable std::unique_ptr<BugType> BT;

		public:
		void checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const;
		bool IsLoop(const Stmt *Stmt, CheckerContext &Ctx) const;
		void CheckLoopCondition(const Stmt *stmt, CheckerContext &Ctx) const;
		bool CheckTaintedStmt(const Stmt *stmt, CheckerContext &Ctx) const;
		bool isArgUnConstrained(SVal Arg, SValBuilder &builder, ProgramStateRef state) const;
		void reportBug(CheckerContext &C) const;
        };
}

void TaintedLoopChecker::reportBug(CheckerContext &Ctx) const {

	if (!BT)
		BT.reset(new BuiltinBug(this, "Tainted Loop Condition"));

	ExplodedNode *N = Ctx.generateNonFatalErrorNode(Ctx.getState());

	if (!N)
		return;

	auto report = std::make_unique<PathSensitiveBugReport>(*BT, "Tainted Branch Condition in Loop Construct", N);

	Ctx.emitReport(std::move(report));
}

// Following code is from isArgUnConstrained by Andrew Ruef written for analyzing OpenSSL bug
// https://blog.trailofbits.com/2014/04/27/using-static-analysis-and-clang-to-find-heartbleed 

bool TaintedLoopChecker::isArgUnConstrained(SVal Arg, SValBuilder &builder, ProgramStateRef state) const {

	bool result = false;
	
	llvm::APInt V(32, 0x10000);
	SVal Val = builder.makeIntVal(V, false);

    	Optional<NonLoc> NLVal = Val.getAs<NonLoc>();

    	if (!NLVal) {
      		return result;
	}

	Optional<NonLoc> NLArg = Arg.getAs<NonLoc>();
    	
	if (!NLArg) {
      		return result;
	}

	SVal  cmprLT = builder.evalBinOp(state,
			BO_GT,
			*NLArg,
			*NLVal,
			builder.getConditionType());

	Optional<DefinedOrUnknownSVal>  NLcmprLT = cmprLT.getAs<DefinedOrUnknownSVal>();

	if (!NLcmprLT) {
		return result;
	}

	std::pair<ProgramStateRef,ProgramStateRef>  p =
		state->assume(*NLcmprLT);

	ProgramStateRef trueState = p.first;

	if (trueState) { 
		result = true;
	}

	return result;
}


bool TaintedLoopChecker::IsLoop(const Stmt *stmt, CheckerContext &Ctx) const {

	const ParentMap &PM = Ctx.getLocationContext()->getParentMap();
	const Stmt *current_stmt = stmt;

	while (PM.hasParent(current_stmt)) {

		unsigned int StmtClass = current_stmt->getStmtClass();
		current_stmt = PM.getParent(current_stmt);

		if (StmtClass == Stmt::CompoundStmtClass)
			return false;
		else if (StmtClass == Stmt::WhileStmtClass)
			return true;
		else if (StmtClass == Stmt::DoStmtClass)
			return true;
		else if (StmtClass == Stmt::ForStmtClass)
			return true;
	}

	return false;
}

bool TaintedLoopChecker::CheckTaintedStmt(const Stmt *stmt, CheckerContext &Ctx) const {

	ProgramStateRef state = Ctx.getState();
	
	if (isTainted(state, Ctx.getSVal(stmt)))
		return true;

	Stmt::const_child_iterator child = stmt->child_begin();

	while (child != stmt->child_end()) {

		if (isTainted(state, Ctx.getSVal(*child))) {
			return true;
		}	

		++child;
	}

	return false;
}

void TaintedLoopChecker::CheckLoopCondition(const Stmt *Condition, CheckerContext &Ctx) const {

        ProgramStateRef state = Ctx.getState();
        SValBuilder &svalBuilder = Ctx.getSValBuilder();
	SVal LoopVarVal;

        if (const BinaryOperator *BinOp = dyn_cast<BinaryOperator>(Condition)) {

                if (BinOp->isComparisonOp()) {
                
			const Expr *RHS = BinOp->getRHS();
                        const Expr *LHS = BinOp->getLHS();

                        SVal RHSVal = Ctx.getSVal(RHS);

                        if (RHSVal.isZeroConstant())
                                Condition = LHS;
                        else
                                Condition = RHS;

                        if (TaintedLoopChecker::CheckTaintedStmt(Condition, Ctx)) {

                                LoopVarVal = Ctx.getSVal(Condition);

                                if (TaintedLoopChecker::isArgUnConstrained(LoopVarVal, svalBuilder, state))
                                        reportBug(Ctx);
                        }
                }

	} else if (TaintedLoopChecker::CheckTaintedStmt(Condition, Ctx)) {

		// handle possible implicit boolean conversions
                if (dyn_cast<Expr>(Condition)->isKnownToHaveBooleanValue()) {

			if (const ImplicitCastExpr *IE = dyn_cast<ImplicitCastExpr>(Condition)) { 
				Condition = IE->getSubExpr();	
			}
		}
		
		if (const UnaryOperator *UnOp = dyn_cast<UnaryOperator>(Condition)) {
			Condition = UnOp->getSubExpr();
		}
		
		LoopVarVal = Ctx.getSVal(Condition);

		if (TaintedLoopChecker::isArgUnConstrained(LoopVarVal, svalBuilder, state))
			reportBug(Ctx);
	}
}

void TaintedLoopChecker::checkBranchCondition(const Stmt *Condition, CheckerContext &Ctx) const {

	if (IsLoop(Condition, Ctx))
		CheckLoopCondition(Condition, Ctx);
}

void ento::registerTaintedLoopChecker(CheckerManager &mgr) {
	mgr.registerChecker<TaintedLoopChecker>();
}

bool ento::shouldRegisterTaintedLoopChecker(const CheckerManager &mgr) {
	return true;
}
