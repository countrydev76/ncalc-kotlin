package io.jopitel.kotlin.ncalc.ncore

/**
 * A group of *members*.
 *
 * @param T
 * @constructor Creates an empty group.
 */
class hjCalcEx<T>(name: String, vararg strings: String) : hjCalc<T>(name, *strings) {
  /**
   * this method is to calculate multiple.
   *
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the multiple result.
   */
  override fun multiple(l: T, r: T): Int {
    return l as Int * r as Int + 2
  }

  /**
   * this method is all sum.
   *
   * @param numbers Int numbers argument.
   * @return Int the sum result.
   */
  fun sum(vararg numbers: Int): Int {
    return numbers.sum()
  }
}