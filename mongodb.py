from pymongo import MongoClient


def mongo():
	MONGODB_URI = "#####"
	client = MongoClient(MONGODB_URI)
	db = client.get_database("userdatabase")
	user_record = db.userdata

	return user_record
