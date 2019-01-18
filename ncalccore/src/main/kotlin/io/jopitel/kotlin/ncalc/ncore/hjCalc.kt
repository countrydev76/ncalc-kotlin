package io.jopitel.kotlin.ncalc.ncore

/**
 * A group of *members*.
 *
 * This class has no useful logic; it's just a documentation example.
 * > link : [kotlin Inheritance](https://play.kotlinlang.org/byExample/01_introduction/07_Inheritance)
 *
 * #### Example
 * ```kotlin
 * open fun multiple(l: T, r: T): Int {
 *   return l as Int * r as Int
 * }
 * ```
 *
 * @param in T the type of a l and r in this group.
 * @property name String the name of this group.
 * @constructor Creates an empty group.
 */
open class hjCalc<in T>(val name: String, vararg strings: String) {

  /**
   * this method is constructor.
   *
   * @param name String calc name
   * @constructor create object
   */
  constructor(name: String) : this(name, "")

  /**
   * this method is to calculate plus.
   *
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the plus result.
   */
  open fun plus(l: T, r: T): Int {
    return l as Int + r as Int
  }

  /**
   * this method is to calculate minus.
   *
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the minus result.
   */
  open fun minus(l: T, r: T): Int {
    return l as Int - r as Int
  }

  /**
   * this method is to calculate multiple.
   *
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the multiple result.
   */
  open fun multiple(l: T, r: T): Int {
    return l as Int * r as Int
  }

  /**
   * this method is to calculate devide.
   *
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the devide result.
   */
  open fun devide(l: T, r: T): Int {
    return l as Int / r as Int
  }
}