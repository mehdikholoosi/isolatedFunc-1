/**
 * @name Use After Free
 * @description Detects uses of memory after it has been freed.
 * @kind problem
 * @problem.severity warning
 * @id cpp/use-after-free
 * @tags security
 */

import cpp

class FreeCall extends Call {
  FreeCall() {
    this.getTarget().hasName("free")
  }
}

class AllocCall extends Call {
  AllocCall() {
    this.getTarget().hasName("malloc") or
    this.getTarget().hasName("calloc") or
    this.getTarget().hasName("realloc")
  }
}

class FreedVariable extends Variable {
  FreedVariable() {
    exists(FreeCall fc |
      fc.getArgument(0).asExpr().getAnAccess().getTarget() = this
    )
  }
}

class UseAfterFree extends Expr {
  UseAfterFree() {
    exists(FreedVariable v |
      this.getAnAccess().getTarget() = v and
      this.getEnclosingFunction() = v.getEnclosingFunction() and
      this.getLocation().getStartLine() > v.getALocalDefinition().getLocation().getEndLine()
    )
  }
}

from UseAfterFree uaf
select uaf, "Potential use after free detected."
