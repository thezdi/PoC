/**
 * @id cpp/untrusted-pointer-dereference
 * @kind path-problem
 * @problem.severity error
 */

import cpp
import DataFlow::PathGraph
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.valuenumbering.GlobalValueNumbering
import semmle.code.cpp.ir.IR
import semmle.code.cpp.ir.implementation.aliased_ssa.internal.AliasedSSA

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
	exists(Instruction ir, string var, VariableAccess va |
	    ir instanceof LoadInstruction
	    and ir.getResultIRType() instanceof IRAddressType
	    and ir.(LoadInstruction).getSourceValueOperand().isDefinitionInexact()
	    and node.asExpr() = ir.getAST().(Expr)
	    // Check type info of virtual variable to filter results. Very specific to MySQL Cluster, rewrite as necessary
	    and va.getEnclosingFunction().getName() = ir.getEnclosingFunction().getName()
	    and var = getOperandMemoryLocation(ir.(LoadInstruction).getSourceValueOperand()).getVirtualVariable().toString().replaceAll("*", "")
	    and va.getTarget().toString() = var
	    and va.getTarget().getType().toString().matches("%Signal%")
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
