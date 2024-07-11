/**
 * @name Buffer Overflow
 * @description Detects potential buffer overflow vulnerabilities using strcpy.
 * @kind problem
 * @problem.severity error
 * @id cpp/buffer-overflow
 * @tags security
 */

import cpp

class StrcpyCall extends FunctionCall {
  StrcpyCall() {
    this.getCallee().getName() = "strcpy"
  }
}

class BufferOverflow extends Expr {
  BufferOverflow() {
    exists(StrcpyCall strcpy | 
      let sourceSize = strcpy.getArgument(1).getType().getSize().toInt() and
      let destSize = strcpy.getArgument(0).getType().getSize().toInt() and
      sourceSize > destSize
      and
      this = strcpy.getArgument(0)
    )
  }
}

from BufferOverflow bo
select bo, "Potential buffer overflow detected using strcpy."
