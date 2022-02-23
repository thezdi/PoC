/**
 * @id cpp/untrusted-loop
 * @kind path-problem
 * @problem.severity warning
 */

import cpp
import DataFlow::PathGraph
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

//ref https://msrc-blog.microsoft.com/2019/03/19/vulnerability-hunting-with-semmle-ql-part-2/

class SystemCfg extends TaintTracking::Configuration {
    SystemCfg() { this = "SystemCfg" }

    override predicate isSource(DataFlow::Node node) {
        exists (FieldAccess va |
            node.asExpr() = va
	    and va.getTarget().hasName("theData")
        )
    }

    override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
        exists(Expr e, FieldAccess fa |
            pred.asExpr() = e
	    and fa.getQualifier*() = e
	    and succ.asExpr() = fa
        )
    }

    override predicate isSink(DataFlow::Node node) {
        exists(Loop lp, Expr cexpr |
	    cexpr = lp.getControllingExpr() and (
	        (
	        cexpr.(ComparisonOperation).getRightOperand().getValue().toInt() = 0
	        and node.asExpr() = cexpr.(ComparisonOperation).getLeftOperand()
	        ) 
	        or node.asExpr() = cexpr.(ComparisonOperation).getRightOperand()
	        or node.asExpr() = cexpr.(UnaryOperation).getOperand()
	    )
        )
    }

    override predicate isSanitizer(DataFlow::Node node) {
        exists(MacroInvocation mi |
            mi.getMacroName().matches("%ptrCheckGuard%")
            and mi.getExpr() = node.asExpr()
        ) or
   
        exists(MacroInvocation mi |
            mi.getMacroName().matches("%arrGuard%")
            and mi.getExpr() = node.asExpr()
        ) or
 
        exists( IfStmt aif, RelationalOperation rop |
            node.asExpr().(VariableAccess).getTarget().getAnAccess() = aif.getControllingExpr().getAChild*()
            and aif.getASuccessor+() = node.asExpr()
            and not ( node.asExpr() = aif.getControllingExpr().getAChild*() )
            and rop = aif.getControllingExpr().getAChild*() 
            and not rop.getRightOperand().getValue().toInt() = 0 // ignore check against 0
        )
    }
}

from DataFlow::PathNode sink, DataFlow::PathNode source, SystemCfg cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, sink.getNode().getLocation().toString()
