/**
 * @id cpp/example/empty-block
 * @kind path-problem
 */

import cpp
import DataFlow::PathGraph
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.valuenumbering.GlobalValueNumbering

class SystemCfg extends TaintTracking::Configuration {
  SystemCfg() { this = "SystemCfg" }

  override predicate isSource(DataFlow::Node node) {
    exists (FieldAccess va |
      node.asExpr() = va
      and
      va.getTarget().getName().matches("theData")
    )
    or
    exists(FunctionCall fc |
      fc.getTarget().hasName("getSection") and
      fc.getArgument(0) = node.asDefiningArgument()
    )
    
  }

  // https://msrc-blog.microsoft.com/2019/03/19/vulnerability-hunting-with-semmle-ql-part-2/
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(Expr e, FieldAccess fa |
      node1.asExpr() = e and node2.asExpr() = fa |
      fa.getQualifier*() = e and not (fa.getParent() instanceof FieldAccess)
    )
  }

  override predicate isSink(DataFlow::Node node) {
    exists (ArrayExpr ae | 
      node.asExpr() = ae.getArrayOffset()
    )
    or
    exists(FunctionCall call |
      (
        call.getTarget().getName() = "memcpy"
        or
        call.getTarget().getName() = "memset"
        or
        call.getTarget().getName() = "memmove"
      )
      and
      node.asExpr() = call.getArgument(2)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(MacroInvocation mi |
      mi.getMacroName().matches("%ptrCheckGuard%")
      and mi.getExpr() = node.asExpr()
    )
    or
    exists( IfStmt aif, RelationalOperation rop |
      node.asExpr().(VariableAccess).getTarget().getAnAccess() = aif.getControllingExpr().getAChild*()
      and aif.getASuccessor+() = node.asExpr()
      and not ( node.asExpr() = aif.getControllingExpr().getAChild*() )
      and rop = aif.getControllingExpr().getAChild*() 
    )
  }

}

from DataFlow::PathNode sink, DataFlow::PathNode source, SystemCfg cfg
where
  cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, sink.getNode().getLocation().toString()


