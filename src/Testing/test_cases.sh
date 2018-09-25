cd "/home/jacob/School/416_ecse/lab1/src/"
javac DnsClient.java


MCGILL="" # Set to true if connected to mcgill network

if MCGILL; then
	echo "############################"
	# Get IP of google.com from mcgill dns
	java DnsClient -r 2 -t 1 @132.206.85.18 google.com
	echo "############################"

	# Get IP of mcgill.ca from mcgill dns
	java DnsClient -r 2 -t 1 @132.206.85.18 mcgill.ca
	echo "############################"
fi

echo "############################"
# Get IP of google.com from google dns
java DnsClient -r 2 -t 1 @8.8.8.8 google.com
echo "############################"

# Get IP of mcgill.ca from google dns
java DnsClient -r 2 -t 1 @8.8.8.8 mcgill.ca
echo "############################"

echo "############################"
# Get IP of gmail.com from google dns
java DnsClient -r 2 -mx -t 1 @8.8.8.8 gmail.com
echo "############################"
