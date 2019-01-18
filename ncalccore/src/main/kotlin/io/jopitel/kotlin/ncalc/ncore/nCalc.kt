package io.jopitel.kotlin.ncalc.ncore

/**
 * User DTO class
 * @property name String
 * @property id Int
 * @constructor
 */
data class User(val name: String, val id: Int)

/**
 * User DTO full class
 * @property balance String
 * @property picture String
 * @property age Int
 * @property name String
 * @property gender String
 * @property company String
 * @property email String
 * @constructor
 */
data class UserFull(
  val balance: String,
  val picture: String,
  var age: Int,
  val name: String,
  val gender: String,
  val company: String,
  val email: String
)

/*
// https://play.kotlinlang.org/byExample/03_special_classes/01_Data%20classes
fun main() {
  val user = User("Alex", 1)
  println(user)                                          // 2

  val secondUser = User("Alex", 1)
  val thirdUser = User("Max", 2)

  println("user == secondUser: ${user == secondUser}")   // 3
  println("user == thirdUser: ${user == thirdUser}")

  println(user.hashCode())                               // 4
  println(thirdUser.hashCode())

  // copy() function
  println(user.copy())                                   // 5
  println(user.copy("Max"))                              // 6
  println(user.copy(id = 2))                             // 7

  println("name = ${user.component1()}")                 // 8
  println("id = ${user.component2()}")
}
*/