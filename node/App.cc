#ifdef _MSC_VER
#pragma warning(disable:4786)
#endif
//=====================================================================================/
#include <iomanip>
#include <vector>
#include <omnetpp.h>
#include "./Packet_m.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iostream>
#include <locale>
#include <codecvt>
#include <thread>
#include <unordered_map>
#include <vector>
//=====================================================================================/
using namespace omnetpp;
//=====================================================================================/
int mfieldnames;
class MaliciousNodeGroup {
private:
    int lowerBound;
    int upperBound;
    std::string code;
    std::vector<int> ratings;
public:
    MaliciousNodeGroup() : lowerBound(0), upperBound(0), code("") {}
     MaliciousNodeGroup(int lower, int upper, const std::string& groupCode)
         : lowerBound(lower), upperBound(upper), code(groupCode) {}
    void addRating(int rating) {
        ratings.push_back(rating);
    }
    bool meetsCondition() const {
        if (ratings.size() < 3)
            return false;
        if (code == "K1") {
            int consecutiveNegatives = 0;
            for (int rating : ratings) {
                if (rating < 0) {
                    consecutiveNegatives++;
                    if (consecutiveNegatives >= 3)
                        return true;
                } else {
                    consecutiveNegatives = 0;
                }
            }
            return false;
        } else if (code == "K2") {
            int consecutiveNegatives = 0;
            int consecutivePositives = 0;
            for (int rating : ratings) {
                if (rating < 0) {
                    consecutiveNegatives++;
                    consecutivePositives = 0;
                    if (consecutiveNegatives >= 3 && consecutivePositives >= 3)
                        return true;
                } else {
                    consecutiveNegatives = 0;
                    consecutivePositives++;
                }
            }
            return false;
        } else if (code == "K3") {
            int consecutivePositives = 0;
            for (int rating : ratings) {
                if (rating >= 0) {
                    consecutivePositives++;
                    if (consecutivePositives >= 3)
                        return true;
                } else {
                    consecutivePositives = 0;
                }
            }
            return false;
        } else {
            std::cerr << "Hatalı grup kodu: " << code << std::endl;
            return false;
        }
    }
};
//=====================================================================================/
class App;
//=====================================================================================/
class MyPacket : public Packet {
private:
    std::string prevHash;
    int nodeRating;
    std::string groupCode;
    int beforeid = 0;
    int afterid = 0;
public:
    MyPacket(const char *name = nullptr, int kind = 0) : Packet(name, kind) {}
    const std::string& getPrevHash() const { return prevHash; }
    void setPrevHash(const std::string& prevHash) { this->prevHash = prevHash; }
    int getNodeRating() const { return nodeRating; }
    void setNodeRating(int rating) { this->nodeRating = rating; }
    const std::string& getGroupCode() const { return groupCode; }
    void setGroupCode(const std::string& code) { this->groupCode = code; }
    int getbeforeid() const { return beforeid; }
    void setbeforeid(int beforeid) { this->beforeid = beforeid; }
    int getafterid() const { return afterid; }
    void setafterid(int afterid) { this->afterid = afterid; }
};
//=====================================================================================/
class Block {
private:
    std::string hash;
    std::string prevHash;
    MyPacket* data;
    time_t timestamp;
    int nodeRating;
public:
    Block(MyPacket* data, const std::string& prevHash);
    std::string calculateHash(const App& app) const;
    std::string getHash() const { return hash; }
    std::string getPrevHash() const { return prevHash; }
    int getNodeRating() const { return nodeRating; }
    void setNodeRating(int rating) { nodeRating = rating; }
    int autorateNode(const App& app) ;
};
//=====================================================================================/
class App : public cSimpleModule {
private:
    //---------------------------------------------------/
    void FileWritingPacketInformation(MyPacket* pk);
    void AttackDetectionRatio(MyPacket *pk, int calcProcess, std::string attackFileName);
    void trust_level();

    std::map<int, int> nodeRatings;

    //---------------------------------------------------/
    int numNodes;
    int myAddress;
    std::vector<int> destAddresses;
    cPar *sendIATime;
    cPar *packetLengthBytes;
    cMessage *generatePacket = nullptr;
    long pkCounter;
    std::vector<Block*> blockchain;
    simsignal_t endToEndDelaySignal;
    simsignal_t hopCountSignal;
    simsignal_t sourceAddressSignal;
    MaliciousNodeGroup K1;
    MaliciousNodeGroup K2;
    MaliciousNodeGroup K3;
public:
    virtual ~App();
    std::string calculateSHA256(const std::string& input) const;
protected:
    virtual void initialize() override;
    void handleMessage(cMessage *msg) override;
    std::string calculateHash(const MyPacket* packet);
    int autorateNode(const MyPacket* packet);
    bool bir_grup_nodun_bir_noda_saldirisi(int attacker, int victim);
    bool bir_grup_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(int puan_veren_node);
    bool bir_grup_nodun_bir_noda_saldirisi_yakalama(MyPacket *pk,int attacker, int victim);
    bool bir_grup_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_yakalama(MyPacket *pk,int puan_veren_node);

};
//=====================================================================================/
Define_Module(App);
//=====================================================================================/
App::~App() {
    cancelAndDelete(generatePacket);
}
//=====================================================================================/
void App::FileWritingPacketInformation(MyPacket* pk) {
    //---------------------------------------------------------------------------------
    //General data files (fulloutput.txt)
    //---------------------------------------------------------------------------------
    std::string fulloutput_fileName = "./datafiles/fulloutput.txt";
    std::ofstream fulloutput_file(fulloutput_fileName, std::ios::app);

    if (fulloutput_file.is_open() ) {
        fulloutput_file << "|Name: " << pk->getName() << "\t"
    << "|Byte Length: " << pk->getByteLength() << "\t"
    << std::setw(14) << std::right << "|Creation Time: " << std::setw(14) << std::right << (std::to_string(pk->getCreationTime().dbl()).length() < 14 ? std::string(14 - std::to_string(pk->getCreationTime().dbl()).length(), ' ') + std::to_string(pk->getCreationTime().dbl()) : std::to_string(pk->getCreationTime().dbl())) << "\t"
    << "|Id: " << pk->getId() << "\t"
    << "|Src Addr.:  " << (pk->getSrcAddr() < 10 ? "  " : (pk->getSrcAddr() < 100 ? " " : "")) << pk->getSrcAddr() << "\t"
    << "|Dest.Addr.: " << (pk->getDestAddr() < 10 ? "  " : (pk->getDestAddr() < 100 ? " " : "")) << pk->getDestAddr() << "\t"
    << "|Before Id: " << (pk->getbeforeid() < 10 ? "  " : (pk->getbeforeid() < 100 ? " " : "")) << pk->getbeforeid() << "\t"
    << "|After Id: " << (pk->getafterid() < 10 ? "  " : (pk->getafterid() < 100 ? " " : "")) << pk->getafterid() << "\t"
    << "|Kind : " << (pk->getKind() < 10 ? "  " : (pk->getKind() < 100 ? " " : "")) << pk->getKind() << "\t"
    << std::setw(14) << std::right << "|Arrival Time: " << std::setw(14) << std::right << (std::to_string(pk->getArrivalTime().dbl()).length() < 14 ? std::string(14 - std::to_string(pk->getArrivalTime().dbl()).length(), ' ') + std::to_string(pk->getArrivalTime().dbl()) : std::to_string(pk->getArrivalTime().dbl())) << "\t"
//  << "|K2.: " << (pk->getArrivalGate() < 10 ? "  " : (pk->getArrivalGate() < 100 ? " " : "")) << pk->getArrivalGate() << "\t"
//  << "|K3.: " << (pk->getArrivalModule() < 10 ? "  " : (pk->getArrivalModule() < 100 ? " " : "")) << pk->getArrivalModule() << "\t"
//  << "|K4.: " << (pk->getArrivalModuleId() < 10 ? "  " : (pk->getArrivalModuleId() < 100 ? " " : "")) << pk->getArrivalModuleId() << "\t"
//  << "|K5.: " << (pk->getClassAndFullName() < 10 ? "  " : (pk->getClassAndFullName() < 100 ? " " : "")) << pk->getClassAndFullName() << "\t"
//  << "|K6.: " << (pk->getClassName() < 10 ? "  " : (pk->getClassName() < 100 ? " " : "")) << pk->getClassName() << "\t"
//  << "|K7.: " << (pk->getContextPointer() < 10 ? "  " : (pk->getContextPointer() < 100 ? " " : "")) << pk->getContextPointer() << "\t"
//  << "|K8.: " << (pk->getControlInfo() < 10 ? "  " : (pk->getControlInfo() < 100 ? " " : "")) << pk->getControlInfo() << "\t"
//  << "|K9.: " << (pk->getDisplayString() < 10 ? "  " : (pk->getDisplayString() < 100 ? " " : "")) << pk->getDisplayString() << "\t"
    << "|K10 : " << (pk->getEncapsulationId() < 10 ? "  " : (pk->getEncapsulationId() < 100 ? " " : "")) << pk->getEncapsulationId() << "\t"
    << "|K11 : " << (pk->getEncapsulationTreeId() < 10 ? "  " : (pk->getEncapsulationTreeId() < 100 ? " " : "")) << pk->getEncapsulationTreeId() << "\t"
    << "|K12 : " << (pk->getHopCount() < 10 ? "  " : (pk->getHopCount() < 100 ? " " : "")) << pk->getHopCount() << "\t"
    << "|K13 : " << (pk->getInsertOrder() < 10 ? "  " : (pk->getInsertOrder() < 100 ? " " : "")) << pk->getInsertOrder() << "\t"
    << "|K14 : " << (pk->getLiveMessageCount() < 10 ? "  " : (pk->getLiveMessageCount() < 100 ? " " : "")) << pk->getLiveMessageCount() << "\t"
    << "|K15 : " << (pk->getLiveObjectCount() < 10 ? "  " : (pk->getLiveObjectCount() < 100 ? " " : "")) << pk->getLiveObjectCount() << "\t"
    << "|K16 : " << (pk->getNamePooling() < 10 ? "  " : (pk->getNamePooling() < 100 ? " " : "")) << pk->getNamePooling() << "\t"
    << "|K17 : " << (pk->getSchedulingPriority() < 10 ? "  " : (pk->getSchedulingPriority() < 100 ? " " : "")) << pk->getSchedulingPriority() << "\t"
 // << "|K18.: " << (pk->getSenderGate() < 10 ? "  " : (pk->getSenderGate() < 100 ? " " : "")) << pk->getSenderGate() << "\t"
 // << "|K9: " << pk->getSenderModule() << "\t"
 // << "|K20: " << pk->getSenderModuleId() << "\t"
    << "|K20 : " << (pk->getSenderModuleId() < 10 ? "  " : (pk->getSenderModuleId() < 100 ? " " : "")) << pk->getSenderModuleId() << "\t"
    << "|K21: " << pk->getSrcProcId() << "\t"
    << "|K22: " << pk->getShareCount() << "\t"
    << "|K23: " << pk->getDescriptor() << "\t"
    << "|K27 : " << (pk->getPreviousEventNumber() < 10 ? "  " : (pk->getPreviousEventNumber() < 100 ? " " : "")) << pk->getPreviousEventNumber() << "\t"
 // << "|K24: " << pk->getOwner() << "\t"
    << "|K25 : " << (pk->getSenderGateId() < 10 ? "  " : (pk->getSenderGateId() < 100 ? " " : "")) << pk->getSenderGateId() << "\t"
 // << "|K26: " << pk->privateDup() << "\t"
    << "|Src. Node Rating: " << (std::to_string(pk->getNodeRating()).length() < 4 ? std::string(4 - std::to_string(pk->getNodeRating()).length(), ' ') + std::to_string(pk->getNodeRating()) : std::to_string(pk->getNodeRating())) << "\t"
    << "|Code: " << pk->getGroupCode() << "\t"
    << "|Prev.Hash: " << pk->getPrevHash() << "\t";

    fulloutput_file << std::endl;
    fulloutput_file.close();
    EV << "Dosyaya içerik başarıyla eklendi: " << fulloutput_fileName << endl;
    } else {
    EV << "Dosya açılamadı: " << fulloutput_fileName << endl;
    }
    //---------------------------------------------------------------------------------
    //Points - Begin
    //---------------------------------------------------------------------------------
    std::string PointsfileName = "./datafiles/Points.txt";
    std::ofstream Points_file(PointsfileName, std::ios::app);
    if (Points_file.is_open() && mfieldnames==0) {
        Points_file << std::setw(10) << std::left << "Source_ID"
                    << std::setw(15) << std::left << "Destination_ID"
                    << std::setw(7) << std::left << "Rating"
                    << std::setw(5) << std::left << "Votes" << std::endl;
        Points_file.close();
        std::cout << "Başlıklar dosyaya yazıldı.1" << std::endl;
      }

    if (Points_file.is_open()) {
        Points_file << std::setw(5) << pk->getbeforeid()
                     << std::setw(13) <<pk->getafterid()
                     << std::setw(11) << pk->getNodeRating()
                     << std::setw(6) << 1 << std::endl;
        //Points_file << std::endl;
        Points_file.close();
        EV << "Dosyaya içerik başarıyla eklendi.1" << std::endl;
        }
      //---------------------------------------------------------------------------------
      //Points - End
      //---------------------------------------------------------------------------------

      //---------------------------------------------------------------------------------
      //Total Points - Begin
      //---------------------------------------------------------------------------------
      std::string PointsTotalfileName = "./datafiles/TotalPoints.txt";
      std::ofstream PointsTotal_file(PointsTotalfileName, std::ios::app);
      // Döngüyü belirli bir süre beklet (örneğin, 1 saniye)
      // std::this_thread::sleep_for(std::chrono::seconds(1));
      struct Data {
          int totalRating = 0;
          int totalVotes = 0;
      };
      std::ifstream inputFile("./datafiles/Points.txt");
      std::ofstream outputFile("./datafiles/TotalPoints.txt");

      if (!inputFile.is_open() || !outputFile.is_open()) {
             std::cout << "Dosya açılamadı! -1" << std::endl;
             return;
         }else
         {
             outputFile << std::setw(15) << std::left << "Destination_ID"
                        << std::setw(13) << std::left << "Total_Rating"
                        << std::setw(12) << std::left << "Total_Votes" << std::endl;
         }
         std::unordered_map<int, Data> destinationData;
         std::string line;
         // Başlık satırını oku ve atla
         std::getline(inputFile, line);
         while (std::getline(inputFile, line)) {
             std::istringstream iss(line);
             int sourceID, destinationID, rating, votes;

             if (!(iss >> sourceID >> destinationID >> rating >> votes)) {
                 std::cout << "Veri okunamadı!" << std::endl;
                 continue; // Hatalı satırı atla
             }

             destinationData[destinationID].totalRating += rating;
             destinationData[destinationID].totalVotes += votes;
         }
         // Sonuçları TotalPoints.txt dosyasına yaz

         for (const auto& entry : destinationData) {
             /*
             outputFile
                << std::setw(5) << " "
                << std::setw(15) << entry.first
                << std::setw(13) << entry.second.totalRating
                << std::setw(6) << entry.second.totalVotes << std::endl;
              */

             outputFile
                 << std::setw(8)  << std::right << entry.first << "\t"
                 << std::setw(9) << std::right << entry.second.totalRating << "\t"
                 << std::setw(10)  << std::right << entry.second.totalVotes << std::endl;


             //outputFile << std::endl;
         }
         inputFile.close();
         outputFile.close();
         std::cout << "İşlem tamamlandı. Sonuçlar TotalPoints.txt dosyasına yazıldı." << std::endl;
      //---------------------------------------------------------------------------------
      //Total Points - eND
      //---------------------------------------------------------------------------------
       trust_level();//Güven seviyesi hesaplama => Güven puanları %25,%50,%75 ve diğer dilimlere giren nodları belirle ve dosya oluştur
       //---------------------------------------------------------------------------------
    //Calculate for Battery Consumption, CPU Usage - Begin
    //---------------------------------------------------------------------------------
    //Parameteters
    double toplamIslemSayisi =  static_cast<double>(rand()) / RAND_MAX * (100.0 - 1.0);
    double islemParcacigiBoyutu = 200.0;//byte
    islemParcacigiBoyutu=islemParcacigiBoyutu;//To avoid unused warning messages during compilation
    double islemBasinaKullanilanCpuYuzdesi = 0.00625;//%
    double islemBasinaGecenSure = 0.1;//saniye (100 ms)
    int pilKapasitesi = 20000;//mAh
    int pilVoltaji = 5;//V (Volt)
    //----
    int toplamIslemSayisi_int = static_cast<int>(round(toplamIslemSayisi));
    double baslangicCpuYuzdesi = 100;//%

    double toplamkullanılanCpuYuzdesi = (toplamIslemSayisi * islemBasinaKullanilanCpuYuzdesi)*100;
    double kalanCpuYuzdesi = baslangicCpuYuzdesi - toplamkullanılanCpuYuzdesi;
    kalanCpuYuzdesi = kalanCpuYuzdesi;//To avoid unused warning messages during compilation
    int pilGucu=  (pilVoltaji * pilKapasitesi)/10000;//W (Watt)

    double toplamPilGucuTuketimi=  (pilGucu*(toplamIslemSayisi*islemBasinaKullanilanCpuYuzdesi))/100;//W

    double toplamEnerjiTuketimiWh = toplamPilGucuTuketimi*(toplamIslemSayisi_int * (islemBasinaGecenSure/3600));//Wh
	double toplamEnerjiTuketimimAh = (toplamEnerjiTuketimiWh/toplamPilGucuTuketimi)*1000;//mAh
    double toplamEnerjiTuketimiYuzdesi= toplamEnerjiTuketimimAh/pilKapasitesi;//Wh %


    //CPU Usage (CpuLevel.txt)
       std::string CpuLevel_fileName = "./datafiles/CpuLevel.txt";
        std::ofstream CpuLevel_file(CpuLevel_fileName, std::ios::app);

         if (CpuLevel_file.is_open() && mfieldnames==0) {
             CpuLevel_file << "Node ID\t"
                           << "CPU Usage (%)\t"
                           << "Total number of transactions" << std::endl;
             CpuLevel_file.close();
             std::cout << "Başlıklar dosyaya yazıldı." << std::endl;
         }
    if (CpuLevel_file.is_open()) {
         CpuLevel_file
         << pk->getafterid() << "\t"
         << std::fixed << std::setprecision(2) << toplamkullanılanCpuYuzdesi << "\t"
         << std::fixed << std::setprecision(0) << toplamIslemSayisi << "\t";
         CpuLevel_file << std::endl;
         CpuLevel_file.close();
         EV << "Dosyaya içerik başarıyla eklendi: " << CpuLevel_fileName << endl;
      }
    //Battery Consumption (BatteryLevel.txt ())
        std::string BatteryLevel_fileName = "./datafiles/BatteryLevel.txt";
           std::ofstream BatteryLevel_file(BatteryLevel_fileName, std::ios::app);

           if (BatteryLevel_file.is_open() && mfieldnames==0) {
               BatteryLevel_file << "Node ID\t"
                                 << "Battery Consumption (%)\t"
                                 << "TotalNumber of Transactions" << std::endl;
               BatteryLevel_file.close();
               mfieldnames += 1;
               std::cout << "Başlıklar dosyaya yazıldı." << std::endl;
           }

           if (BatteryLevel_file.is_open() ) {
                   BatteryLevel_file << pk->getafterid() << "\t"
                   /*
                   << "toplamIslemSayisi_int: " << toplamIslemSayisi_int << "\t"
                   << "baslangicCpuYuzdesi: " << baslangicCpuYuzdesi << "\t"
                   << "toplamkullanılanCpuYuzdesi: " << toplamkullanılanCpuYuzdesi << "\t"
                   << "kalanCpuYuzdesi: " << kalanCpuYuzdesi << "\t"
                   << "pilGucu : " << pilGucu << "\t"
                   << "toplamPilGucuTuketimi: " << toplamPilGucuTuketimi << "\t"
                   << "toplamEnerjiTuketimiWh: " << toplamEnerjiTuketimiWh << "\t"
                   << "toplamEnerjiTuketimimAh: " << toplamEnerjiTuketimimAh << "\t"
                   */
                   <<std::fixed <<  std::setprecision(8) << std::round(toplamEnerjiTuketimiYuzdesi*100000000)/100000000.0 << "\t"
                   << std::fixed << std::setprecision(0) << toplamIslemSayisi << "\t";
                   BatteryLevel_file << std::endl;
                   BatteryLevel_file.close();
                   EV << "Dosyaya içerik başarıyla eklendi." << std::endl;
       }
    //---------------------------------------------------------------------------------
    //Calculate for Battery Consumption, CPU Usage - End
    //---------------------------------------------------------------------------------


}
//=====================================================================================/
void App::initialize() {
    numNodes = 50;
    myAddress = par("address");
    packetLengthBytes = &par("packetLength");
    sendIATime = &par("sendIaTime");
    pkCounter = 0;
    std::string prevHash = "INITIAL_HASH_VALUE";
    WATCH(pkCounter);
    WATCH(myAddress);
    const char *destAddressesPar = par("destAddresses");
    cStringTokenizer tokenizer(destAddressesPar);
    const char *token;
    while ((token = tokenizer.nextToken()) != nullptr)
          destAddresses.push_back(atoi(token));
    if (destAddresses.size() == 0)
       throw cRuntimeError("At least one address must be specified in the destAddresses parameter!");
    generatePacket = new cMessage("nextPacket");
    scheduleAt(sendIATime->doubleValue(), generatePacket);
    endToEndDelaySignal = registerSignal("endToEndDelay");
    hopCountSignal = registerSignal("hopCount");
    sourceAddressSignal = registerSignal("sourceAddress");
    K1 = MaliciousNodeGroup(1, 20, "K1");
    K2 = MaliciousNodeGroup(21, 40, "K2");
    K3 = MaliciousNodeGroup(41, 50, "K3");
    MyPacket *genesisPacket = new MyPacket("Genesis Block");
    genesisPacket->setByteLength(packetLengthBytes->intValue());
    genesisPacket->setKind(intuniform(0, 7));
    genesisPacket->setSrcAddr(myAddress);
    genesisPacket->setDestAddr(destAddresses[intuniform(0, destAddresses.size() - 1)]);
    genesisPacket->setPrevHash(prevHash);
    Block *genesisBlock = new Block(genesisPacket, prevHash);
    blockchain.push_back(genesisBlock);
}
//=====================================================================================/
//=====================================================================================/
void App::handleMessage(cMessage *msg) {

    if (msg == generatePacket) {
        int destAddress;
        do {
            destAddress = intuniform(1, numNodes);
        } while (destAddress == myAddress || destAddress == 50);
        char pkname[40];
        sprintf(pkname, "pk-%d-to-%d-#%ld", myAddress, destAddress, pkCounter++);
        EV << "generating packet " << pkname << endl;
        MyPacket *pk = new MyPacket(pkname);
        pk->setByteLength(packetLengthBytes->intValue());
        pk->setKind(intuniform(0, 7));
        pk->setSrcAddr(myAddress);
        pk->setDestAddr(destAddress);
        pk->setPrevHash(blockchain.back()->getHash());
        pk->setNodeRating(autorateNode(pk));

        if (K1.meetsCondition())
            pk->setGroupCode("K1");
        else if (K2.meetsCondition())
            pk->setGroupCode("K2");
        else if (K3.meetsCondition())
            pk->setGroupCode("K3");
        else
        pk->setGroupCode("None");
        pk->setbeforeid(myAddress);
        pk->setafterid(destAddress);
        Block *newBlock = new Block(pk, blockchain.back()->getHash());
        blockchain.push_back(newBlock);

        //----------------------------------------------------------//
        //Attack mechanism calling
        //----------------------------------------------------------//
        int victim = pk->getDestAddr();
        int attacker = myAddress;
        int attack_value=0;


        if (bir_grup_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(attacker)) {
                getParentModule()->bubble("Attack (Scenario 1)");
                attack_value=1;
            }


        if (bir_grup_nodun_bir_noda_saldirisi(attacker, victim)) {
                       getParentModule()->bubble("Attack (Scenario 2)");
                       attack_value=1;
                   }
        if (attack_value > 0)  {
            send(pk, "out");
        }

        //----------------------------------------------------------//
        //Trust mechanism calling
        //----------------------------------------------------------//
        scheduleAt(simTime() + sendIATime->doubleValue(), generatePacket);
           if (hasGUI()){
               //getParentModule()->bubble("Generating packet for blockchain...");
               FileWritingPacketInformation(pk);


           }
  } else {
             MyPacket *pk = check_and_cast<MyPacket *>(msg);
             EV << "received packet " << pk->getName() << " after " << pk->getHopCount() << "hops" << endl;
             emit(endToEndDelaySignal, simTime() - pk->getCreationTime());
             emit(hopCountSignal, pk->getHopCount());
             emit(sourceAddressSignal, pk->getSrcAddr());
             if (hasGUI()){
                 getParentModule()->bubble("Arrived!");
                 FileWritingPacketInformation(pk);
                 }
              delete pk;
            }
  }
//=====================================================================================/
//Attack mechanisms functions
//=====================================================================================/
bool App::bir_grup_nodun_bir_noda_saldirisi(int attacker, int victim) {
    if (attacker >= 1 && attacker <= 10 && victim == 30 ) {
        return true;
    } else {
        return false;
    }
}

bool App::bir_grup_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(int puan_veren_node) {
     if (puan_veren_node >= 11 && puan_veren_node <= 20 ) {
        return true;
    } else {
        return false;
    }
}
//=====================================================================================/
//Trust mechanisms functions
//=====================================================================================/
bool App::bir_grup_nodun_bir_noda_saldirisi_yakalama( MyPacket *pk, int attacker, int victim) {
    if (attacker >= 1 && attacker >= 10 && victim == 5 ) {
        FileWritingPacketInformation(pk);
        return true;
    } else {
        return false;
    }
}

bool App::bir_grup_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_yakalama( MyPacket *pk, int puan_veren_node) {
     if (puan_veren_node >= 1 && puan_veren_node >= 10 ) {
         FileWritingPacketInformation(pk);
         return true;
    } else {
        return false;
    }
}
//=====================================================================================/
void App::AttackDetectionRatio(MyPacket *pk, int calcProcess, std::string attackFileName) {
         std::ofstream dosya("./datafiles/"+attackFileName);
         double attack_orani[] = {0.1, 0.2, 0.3, 0.4, 0.5};
         double detection_orani[] = {0.1, 0.2, 0.3, 0.4, 0.5};
         srand(time(0));
         dosya << "Percent\tAttack\tDetection\tRatio\n";
          for (int i = 0; i < 5; ++i) {
                 int attack = calcProcess * attack_orani[i];
                 int detection = (int)round((double)attack * ratio);
                 int n = (i == 0) ? 10 : (i+1) * 10;

                 dosya << std::setw(4) << n << std::setw(8) << attack << std::setw(9) << detection << std::setw(11) << std::fixed << std::setprecision(2) << ratio << "\n";

          }
         dosya.close();
         std::cout << "Veriler dosyaya yazıldı.\n";
 }
//=====================================================================================/


//----------------------------------
//Start
//----------------------------------

//----------------------------------
//Değişkenleri tanımla
//----------------------------------
struct Record {
int Node;
int Rating;
int Votes;
int Serial_no; // Yeni eklenen sıra numarası
double Percent; // Yeni eklenen sütun
// Karşılaştırma fonksiyonu
static bool compareRecords(const Record& a, const Record& b) {
return a.Rating > b.Rating;
}
};


void App::trust_level() {
//----------------------------------
// Dosyadan verileri okuma
//----------------------------------
std::ifstream inputFile("./datafiles/TotalPoints.txt");
if (!inputFile.is_open()) {
std::cout << "Dosya bulunamadı!" << endl;
return  ;
}

std::vector<Record> records;
std::string line;

   // Başlık satırını oku ve atla
   std::getline(inputFile, line);

   while (std::getline(inputFile, line)) {
       std::istringstream iss(line);
       Record temp;
           if (!(iss >> temp.Node >> temp.Rating >> temp.Votes)) {

           std::cout << "Veri okunamadı!" << std::endl;
           continue; // Hatalı satırı atla
       }
       records.push_back(temp);

   }
   inputFile.close();

//----------------------------------
// Total_Rating'e göre azalan şekilde sıralama
//----------------------------------
std::sort(records.begin(), records.end(), Record::compareRecords);
//----------------------------------
// Sıra numarası ve yeni sütun değerlerini hesaplama
//----------------------------------
double quarter = numNodes * 0.25;
   double half = numNodes * 0.50;
   double three_quarters = numNodes * 0.75;

   for (size_t i = 0; i < records.size(); ++i) {
       records[i].Serial_no = i + 1;
       if (i < quarter) {
           records[i].Percent = 25.0;
       } else if (i < half) {
           records[i].Percent = 50.0;
       } else if (i < three_quarters) {
           records[i].Percent = 75.0;
       } else {
           records[i].Percent = 100.0;
       }
   }

//----------------------------------
// Çıktıyı yazdırma
//----------------------------------
std::ofstream outFile("./datafiles/Trust_Level.txt");
if (!outFile.is_open()) {
std::cout << "Çıktı dosyası oluşturulamadı!" << std::endl;
return;
}

outFile << "Node\tRating\tVotes\tSerial_no\tPercent" << std::endl;
for (const auto& record : records) {

outFile
        << std::setw(2) << record.Node << "\t"
        << std::setw(7) << record.Rating << "\t"
        << std::setw(7) << record.Votes << "\t"
        << std::setw(9) << record.Serial_no << "\t"
        << std::setw(8) << record.Percent << std::endl;

std::cout << "Çıktı Trust_Level dosyasına yazdırıldı !" << std::endl;
}

std::cout << "Çıktı Trust_Level dosyasına yazdırılması bitti !" << std::endl;
outFile.close();
//----------------------------------
//End
//----------------------------------
}
//=====================================================================================/
int App::autorateNode(const MyPacket* packet) {
    int min = -100;
    int max = 100;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
//=====================================================================================/
std::string App::calculateHash(const MyPacket* packet) {
    std::string packetInfo = packet->getName() +
                            std::to_string(packet->getByteLength()) +
                            std::to_string(packet->getCreationTime().dbl()) +
                            std::to_string(packet->getNodeRating());
    return calculateSHA256(packetInfo);
}
//=====================================================================================/
std::string App::calculateSHA256(const std::string& input) const {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hash_hex + i * 2, "%02x", hash[i]);
    }
    hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
    return std::string(hash_hex);
}
//=====================================================================================/
Block::Block(MyPacket* data, const std::string& prevHash) {
    this->data = data;
    this->prevHash = prevHash;
    this->timestamp = time(nullptr);
    this->hash = calculateHash(App());
    this->nodeRating = autorateNode(App());
 }
//=====================================================================================/
std::string Block::calculateHash(const App& app) const {
    std::string blockInfo = prevHash + data->getName() +
                            std::to_string(data->getByteLength()) +
                            std::to_string(timestamp) +
                            std::to_string(data->getNodeRating());
    return app.calculateSHA256(blockInfo);
}
//=====================================================================================/
int Block::autorateNode(const App& app) {
    int min = -100;
    int max = 100;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
//=====================================================================================/

