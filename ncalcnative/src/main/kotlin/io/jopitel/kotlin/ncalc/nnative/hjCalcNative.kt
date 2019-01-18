package io.jopitel.android.ncalc.nnative

/**
 * This class is jni native class
 *
 * https://www.jetbrains.com/help/idea/setting-up-jni-development-in-gradle-project.html
 * https://docs.gradle.org/current/userguide/native_software.html
 * http://tocea.github.io/gradle-cpp-plugin/
 *
 * - source
 *   https://github.com/avu/gcj -> helloworld sample
 *   https://github.com/gradle/native-samples
 *   https://github.com/JetBrains/kotlin-native
 */
class hjCalcNative {
  /**
   * A native method that is implemented by the 'native-lib' native library,
   * which is packaged with this application.
   */
  external fun stringFromJNI(): String

  /**
   *
   */
  companion object {
    // Used to load the 'native-lib' library on application startup.
    init {
      System.loadLibrary("native-lib")
    }
  }
}
