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
const int sensor_pin = A0;
DHT dht(DHTPIN, DHT11);

#include <ESP8266WiFi.h>

// include ESP8266 Non-OS SDK functions
extern "C" 
{
    #include "user_interface.h"
}


// ===== SETTINGS ===== //
#define LED 2              /* LED pin (2=built-in LED) */
#define LED_INVERT true    /* Invert HIGH/LOW for LED */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13/*,14*/ };

// ===== Runtime variables ===== //
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
WiFiClient client;
const int pingsize = 65535;

// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) 
{
    if (!buf || len < 28) return; // Drop packets without MAC header

    byte pkt_type = buf[12]; // second half of frame control field
  //byte* addr_a = &buf[16]; // first MAC address
  //byte* addr_b = &buf[22]; // second MAC address

  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type >= sizeof(pingsize)) 
  { 
//    Serial.println("ATTACK DETECTED");
//    Serial.println("Hping Attack Detected");
    ++packet_rate;
  }
}

// ===== Attack detection functions ===== //
void attack_started() 
{
    digitalWrite(LED, !LED_INVERT); // turn LED on
    Serial.println("ATTACK DETECTED");
     Serial.println("T50 Attack Detected");
}

void attack_stopped() 
{
    digitalWrite(LED, LED_INVERT); // turn LED off
    Serial.println("ATTACK STOPPED");
}
void setup() 
{
    Serial.begin(SERIAL_BAUD); // Start serial communication

    pinMode(LED, OUTPUT); // Enable LED pin
    digitalWrite(LED, LED_INVERT);
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



  Serial.println("Started \\o/");
}


void loop() 
{
   unsigned long current_time = millis(); // Get current time (in ms)
      int st;
      float h = dht.readHumidity();
      float t = dht.readTemperature();
      float m;
      m = ( 100.00 - ( (analogRead(sensor_pin)/1023.00) * 100.00 ) );
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
                             postStr +="&field3=";
                             postStr += String(m);
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
                             Serial.print("%, Soil Moisture:");
                             Serial.print(m);
                             Serial.println("%. Send to Thingspeak.");
                        }

                        else // if not connected
                        {
                            /*st= millis();
                            while(!client.connect(server,80)) // enters the loop if not connected to the server
                            {
                                yield();
                                if((millis()-st)>60000) // substract curretn time from prevoius time if it is greater than 1 min (60000 millisecond) print "Time out"
                                {
                                    Serial.println("Anomaly Occured");
                                    break; // break the loop ones print "time out" otherwise it will continuesly print "time out"
                                }
                            }*/
                                                                    // Disconnect from any saved or active WiFi connections
                            wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
                            wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
                            wifi_set_channel(channels[0]);        // Set channel
                            wifi_promiscuous_enable(true);       // Enable sniffer
                                   // Update each second (or scan-time-per-channel * channel-range)
                            if (current_time - update_time >= (sizeof(channels)*CH_TIME)) 
                            {
                                update_time = current_time; // Update time variable

                                // When detected deauth packets exceed the minimum allowed number
                                if (packet_rate >= PKT_RATE) 
                                {
                                    ++attack_counter; // Increment attack counter
                                } 
                                else 
                                {
                                    if(attack_counter >= PKT_TIME) 
                                    {
                                        attack_stopped();
                                        attack_counter = 0; // Reset attack counter
                                    }
                                }

                                // When attack exceeds minimum allowed time
                                if (attack_counter == PKT_TIME) 
                                {
                                    attack_started();
                                }

                                Serial.print("Packets/s: ");
                                Serial.println(packet_rate);

                                packet_rate = 0; // Reset packet rate
                            }

                            // Channel hopping
                            if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) 
                            {
                                ch_time = current_time; // Update time variable

                                // Get next channel
                                ch_index = (ch_index+1) % (sizeof(channels)/sizeof(channels[0]));
                                short ch = channels[ch_index];

                                  // Set channel
                                //Serial.print("Set channel to ");
                              //Serial.println(ch);
                              wifi_set_channel(ch);
                            }
                                  
                        }
          delay(1000);              
          client.stop();
          Serial.println("Waiting...");
          
  delay(1000);
        

}
