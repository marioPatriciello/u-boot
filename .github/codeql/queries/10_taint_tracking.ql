
/**
 * @name Network byte-swap values reaching memcpy
 * @description Tracks data from ntoh macros to memcpy size arguments.
 * @kind path-problem
 * @problem.severity warning
 * @id cpp/uboot/network-to-memcpy
 */

 import cpp
 import semmle.code.cpp.dataflow.new.TaintTracking
 
 // Identify expressions resulting from network byte-swap macros
 class NetworkByteSwap extends Expr {
   NetworkByteSwap() {
     exists(MacroInvocation mi |
       mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and
       this = mi.getExpr()
     )
   }
 }
 
 // Define the taint-tracking configuration
 module Config implements DataFlow::ConfigSig {
 
   // Source: expressions associated with ntoh macros
   predicate isSource(DataFlow::Node source) {
     source.asExpr() instanceof NetworkByteSwap
   }
 
   // Sink: third argument (size) of memcpy
   predicate isSink(DataFlow::Node sink) {
     exists(FunctionCall call |
       call.getTarget().getName() = "memcpy" and
       sink.asExpr() = call.getArgument(2)
     )
   }
 }
 
 // Build the global taint-tracking analysis
 module Flow = TaintTracking::Global<Config>;
 
 import Flow::PathGraph
 
 // Find paths from sources to sinks
 from Flow::PathNode source, Flow::PathNode sink
 where Flow::flowPath(source, sink)
 select sink.getNode(), source, sink,
   "Network byte-swap value flows to memcpy size"
 