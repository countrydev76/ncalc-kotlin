package io.jopitel.kotlin.ncalc.ncore;

import org.jetbrains.annotations.Contract;

/**
 * - Kotline HelloWorld
 *   https://www.programiz.com/kotlin-programming/hello-world
 *
 * - Using Android Gradle Multi Project
 *   http://fsd-jinss.tistory.com/39
 */

public class hjCalcJ {
  /**
   * this method is to calculate plus.
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the plus result.
   */
  @Contract(pure = true)
  public static int plus(int l, int r) {
    return l + r;
  }

  /**
   * this method is to calculate minus.
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the minus result.
   */
  @Contract(pure = true)
  public static int minus(int l, int r) {
    return  l - r;
  }

  /**
   * this method is to calculate multiple.
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the multiple result.
   */
  @Contract(pure = true)
  public static int multiple(int l, int r) {
    return l * r;
  }

  /**
   * this method is to calculate devide.
   * @param l T left argument.
   * @param r T right argument.
   * @return Int the devide result.
   */
  @Contract(pure = true)
  public static int devide(int l, int r) {
    return l / r;
  }
}