package networks;

import node.Node;
import builder.NetBuilder;

network Dynamic
{
        parameters:
        @display("bgb=800,500");
  	   @display("i=block/switch");
       @figure[status](type=group; transform=translate(700,20));
       @figure[status.bg](type=rectangle; pos=0,0; size=150,100; anchor=n; cornerRadius=10; fillColor=#fafdb9; fillOpacity=0.2; lineColor=#fafdb9; lineOpacity=0.4);
       @figure[status.distanceTitle](type=text; pos=0,20; text="Attack Count"; anchor=center);
       @figure[status.distance](type=text; pos=0,40; text="0m"; anchor=center; font=Arial,22);
       @figure[status.headingTitle](type=text; pos=0,70; text="Number of detections"; anchor=center);
       @figure[status.heading](type=text; pos=0,90; text="26"; anchor=center; font=Arial,22);
        

    submodules:
        builder: NetBuilder {
        nodesFile = "networks/nodes.txt";
        connectionsFile = "networks/connections.txt";
        }
        
        
       // status.distance alt modülünün tanımı
     
}
 


