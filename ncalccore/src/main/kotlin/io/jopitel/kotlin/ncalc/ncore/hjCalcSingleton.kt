package io.jopitel.kotlin.ncalc.ncore

/**
 * This class is singleton object.
 */
object hjCalcSingleton {
  /**
   * This metbhod is to plus
   *
   * @param l Int left argument.
   * @param r Int right argument.
   * @return Int the plus result.
   */
  @JvmStatic
  fun plus(l: Int, r: Int): Int {
    return l + r
  }

  /**
   * This metbhod is to minus
   *
   * @param l Int left argument.
   * @param r Int right argument.
   * @return Int the minus result.
   */
  fun minus(l: Int, r: Int): Int {
    return l - r
  }

  /**
   * This metbhod is to multiple
   *
   * @param l Int left argument.
   * @param r Int right argument.
   * @return Int the multiple result.
   */
  fun multiple(l: Int, r: Int): Int {
    return l * r
  }

  /**
   * This metbhod is to devide
   *
   * @param l Int left argument.
   * @param r Int right argument.
   * @return Int the devide result.
   */
  fun devide(l: Int, r: Int): Int {
    return l / r
  }
}