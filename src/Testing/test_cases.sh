cd "/home/jacob/School/416_ecse/lab1/src/" # replace with directory of source code
javac DnsClient.java

# -p is untested because idk of any dns servers that don't use port 53 by default
# nonauth/auth is untested because it seems that authoritative dns servers don't support recursive queries

MCGILL="" # Set to true if connected to mcgill network

if MCGILL; then
	DNS="132.206.85.18"
else
	DNS="8.8.8.8"
fi

echo "############################"
echo --Get IP of NonExistant domain-
java DnsClient -r 1 -t 1 @"$DNS" googlasdasd12312e.com
echo "############################"

echo "############################"
echo --Get IP of google.com--
java DnsClient -r 1 -t 1 @"$DNS" google.com
echo "############################"

echo "############################"
echo --Get IP of mcgill.ca--
java DnsClient -r 1 -t 1 @"$DNS" mcgill.ca
echo "############################"

echo "############################"
echo --Get IP of gmail.com--
java DnsClient -r 1 -mx -t 1 @"$DNS" gmail.com
echo "############################"

echo "############################"
echo --Get authoritative name server of google.com--
java DnsClient -ns @"$DNS" google.com # returns ns1google.com among other records
echo "############################"

echo "############################"
echo --Get IP of authoritative name server of google.com--
java DnsClient @"$DNS" ns1google.com
echo "############################"

echo "############################"
echo --get IP of google.com from authoritative name server--
java DnsClient @108.61.19.11 google.com # this should throw an exception - recursive queries are not supported
echo "############################"
