import org.apache.spark.{SparkConf, SparkContext}
// import org.apache.spark.sql.SQLContext

//set up the spark configuration and create contexts
val sparkConf = new SparkConf().setMaster("local").setAppName("BigBrainSecurity")
// your handle to SparkContext to access other context like SQLContext
val sc = new SparkContext(sparkConf)

val rdd = sc.parallelize("/Users/xan0/Documents/security/wikipedia.dat").persist()

val result= rdd.map(article => )


print(result)

sc.stop()