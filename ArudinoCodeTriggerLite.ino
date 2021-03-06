#include <ThingSpeak.h>
#include <Arduino.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <DHT.h>  // Including library for dht
#include <WiFiClient.h> 
String apiKey = "YWEFRSBO8QVAN6FY";     //  Enter your Write API key from ThingSpeak
 
const char *ssid =  "Keralavision";     // replace with your wifi ssid and wpa2 key
const char *pass =  "12345678";
const char* server = "api.thingspeak.com";
#define DHTPIN 0 //pin where the dht11 is connected
DHT dht(DHTPIN, DHT11);

WiFiClient client;
void setup() 
{
       Serial.begin(115200);
       delay(10);
       dht.begin();
       Serial.println("Connecting to ");
       Serial.println(ssid);
       WiFi.begin(ssid, pass);
 
      while (WiFi.status() != WL_CONNECTED) 
     {
            delay(500);
            Serial.print(".");
     }
      Serial.println("");
      Serial.println("WiFi connected");
}
void loop() 
{
      int st;
      float h = dht.readHumidity();
      float t = dht.readTemperature();
              if (isnan(h) || isnan(t)) 
                 {
                     Serial.println("Failed to read from Sensors!");
                      return;
                 }
                         if (client.connect(server,80))   //   "184.106.153.149" or api.thingspeak.com
                      {  
                             String postStr = apiKey;
                             postStr +="&field1=";
                             postStr += String(t);
                             postStr +="&field2=";
                             postStr += String(h);
                             postStr += "\r\n\r\n";
 
                             client.print("POST /update HTTP/1.1\n");
                             client.print("Host: api.thingspeak.com\n");
                             client.print("Connection: close\n");
                             client.print("X-THINGSPEAKAPIKEY: "+apiKey+"\n");
                             client.print("Content-Type: application/x-www-form-urlencoded\n");
                             client.print("Content-Length: ");
                             client.print(postStr.length());
                             client.print("\n\n");
                             client.print(postStr);
                             Serial.print("Temperature: ");
                             Serial.print(t);
                             Serial.print(" degrees Celcius, Humidity: ");
                             Serial.print(h);
                             Serial.println("%. Send to Thingspeak.");
                        }

                        else // if not connected
                        {
                          st= millis(); // get current working time of arduino in milliseconds
                          while(!client.connect(server,80)) // enters the loop if not connected to the server
                            {
                               if((millis()-st)>60000) // substract curretn time from prevoius time if it is greater than 1 min (60000 millisecond) print "Time out"
                                  {
                                  Serial.println("Anomaly Occured");
                                  break; // break the loop ones print "time out" otherwise it will continuesly print "time out"
                                  }
                            }
                        }
          delay(1000);              
          client.stop();
          Serial.println("Waiting...");
          
  delay(1000);
        

}
