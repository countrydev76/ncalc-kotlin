package io.jopitel.kotlin.ncalc.nemail;

import io.jopitel.kotlin.ncalc.ncore.hjCalcJ;

public class hjCalcEmailMainJ {
  /**
   * io.jopitel.kotlin.ncalc.ncalcpush.main define
   * @param args : support multi parameter
   */
  public static void main(String[] args) {
    int left = 4;
    int right = 2;

    System.out.println("-------------------------------------------");
    System.out.println("- hjCalcEmailMainJ");
    System.out.println("-------------------------------------------");
    System.out.println(left + " + " + right + " = " + hjCalcJ.plus(left, right));
    System.out.println(left + " - " + right + " = " + hjCalcJ.minus(left, right));
    System.out.println(left + " * " + right + " = " + hjCalcJ.multiple(left, right));
    System.out.println(left + " / " + right + " = " + hjCalcJ.devide(left, right));
  }
}
