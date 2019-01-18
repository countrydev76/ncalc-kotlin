package io.jopitel.kotlin.ncalc.nnative;

public class HelloWorld {
  public native void print();
  static {
    System.loadLibrary("hello");
  }
}