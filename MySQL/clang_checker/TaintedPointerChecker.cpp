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

	class TaintedPointerChecker : public Checker<check::Location> {

		mutable std::unique_ptr<BugType> BT;

		public:
		void checkLocation(SVal L, bool IsLoad, const Stmt *S, CheckerContext &Ctx) const;
		void reportBug(CheckerContext &C) const;
	};
}

void TaintedPointerChecker::reportBug(CheckerContext &Ctx) const {

	if (!BT)
		BT.reset(new BuiltinBug(this, "Tainted Pointer Load"));

	ExplodedNode *N = Ctx.generateNonFatalErrorNode(Ctx.getState());

	if (!N)
		return;

	auto report = std::make_unique<PathSensitiveBugReport>(*BT, "Pointer Loaded From Tainted Source", N);

	Ctx.emitReport(std::move(report));
}

void TaintedPointerChecker::checkLocation(SVal L, bool IsLoad, const Stmt *stmt, CheckerContext &Ctx) const {

	if (!IsLoad)
		return;

	if (isTainted(Ctx.getState(), L)) {
		const Expr *expr = dyn_cast<Expr>(stmt)->IgnoreImplicitAsWritten();
		if (expr && expr->getType()->isPointerType())
			reportBug(Ctx);
	}
}

void ento::registerTaintedPointerChecker(CheckerManager &mgr) {
	mgr.registerChecker<TaintedPointerChecker>();
}

bool ento::shouldRegisterTaintedPointerChecker(const CheckerManager &mgr) {
	return true;
}
