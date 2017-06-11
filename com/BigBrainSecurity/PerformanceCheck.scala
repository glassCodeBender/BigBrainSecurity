package com.BigBrainSecurity

/**
	* Created by xan0 on 5/21/17.
	*/
trait PerformanceCheck {

	/*
 *  The function below is used to time a method to see how long it takes to run.
 *  Use the method on the method and inside a worksheet and see how efficient it runs.
 *
 *  Example:
 *
 *  //approach # 1
 *  1 to 1000 by 1 toList
 *  //approach #2
 *  List.range(1,1000, 1)
 *
 *  Instead of writing the code below:
 *  val list = List.range(1,1000, 1)
 *
 *  Write:
 *  var list = time {List.range(1,1000, 1)} // it will show you : Elapsed time: 104000ns
 *
 *  Compare to:
 *  var list = time {1 to 1000 by 1 toList} // it will show you : Elapsed time: 93000ns
 */
	/**********************METHOD TO TEST RUNTIME OF A METHOD OR PROCESS******************************
		*                     See collapsed code above for more details.                               *
		*          http://biercoff.com/easily-measuring-code-execution-time-in-scala/                  *
		*************************************************************************************************/

	def time[R](block: => R): R = {
		val t0 = System.nanoTime()
		val result = block    // call-by-name
		val t1 = System.nanoTime()
		println("Elapsed time: " + (t1 - t0) + "ns")
		result
	} // END time()
}
