package io.jopitel.kotlin.ncalc.npush

import io.jopitel.kotlin.ncalc.ncore.hjCalc
import io.jopitel.kotlin.ncalc.ncore.hjCalcEx
import io.jopitel.kotlin.ncalc.ncore.hjCalcMain
import io.jopitel.kotlin.ncalc.ncore.hjCalcSingleton

/**
 *
 */
object hjCalcPushMain {
  /**
   *
   * @param args Array<String>
   */
  @JvmStatic fun main(args: Array<String>) {
    val left = 4
    val right = 2

    println("-------------------------------------------")
    println("- hjCalcEmailMain - call hjCalcMain.main")
    println("-------------------------------------------")
    hjCalcMain.main(arrayOf(""))

    println("-------------------------------------------")
    println("- hjCalcPushMain - hjCalcSingleton test")
    println("-------------------------------------------")
    println("${left} + ${right}  = ${hjCalcSingleton.plus(left, right)}")
    println("${left} - ${right}  = ${hjCalcSingleton.minus(left, right)}")
    println("${left} * ${right}  = ${hjCalcSingleton.multiple(left, right)}")
    println("${left} / ${right}  = ${hjCalcSingleton.devide(left, right)}")

    println("-------------------------------------------")
    println("- hjCalcPushMain - hjCalc test")
    println("-------------------------------------------")
    val calc = hjCalc<Int>("magmajo", "1", "2")
    println("${left} + ${right}  = ${calc.plus(left, right)}")
    println("${left} - ${right}  = ${calc.minus(left, right)}")
    println("${left} * ${right}  = ${calc.multiple(left, right)}")
    println("${left} / ${right}  = ${calc.devide(left, right)}")

    println("-------------------------------------------")
    println("- hjCalcPushMain - hjCalcEx test")
    println("-------------------------------------------")
    val calcEx = hjCalcEx<Int>("magmajo")
    println("${left} + ${right}  = ${calcEx.plus(left, right)}")
    println("${left} - ${right}  = ${calcEx.minus(left, right)}")
    println("${left} * ${right}  = ${calcEx.multiple(left, right)}")
    println("${left} / ${right}  = ${calcEx.devide(left, right)}")
    println("sum(1,2,3,4,5,6)    = ${calcEx.sum(1,2,3,4,5,6)}")
  }
}