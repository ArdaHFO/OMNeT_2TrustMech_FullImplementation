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
#include <map>
#include <string>  // Include this header for string type
//=====================================================================================/
using namespace omnetpp;
using namespace std;
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
};
//=====================================================================================/
class App : public cSimpleModule {
private:
    cTextFigure *textFigure1; // textFigure değişkenini tanımlayın
    //---------------------------------------------------/
    void FilesWritingPacketInformation(MyPacket* pk);
    void FileWrite_Full_txt(MyPacket* pk);
    void FileWrite_Points_txt(MyPacket* pk);
    void FileWrite_TotalPoints_txt(MyPacket* pk);
    void FileWrite_TrustLevel_txt();
    void FileWrite_CpuLevel_txt_And_BatteryLevel_txt(MyPacket* pk);
    void AttackDetectionRatio(MyPacket *pk, int calcProcess, double min_ratio,double max_ratio, std::string attackFileName);
    std::map<int, int> nodeRatings;
    void GroupedNetworkData();
    void GroupedNetworkDataWithTotalVotes();

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
    bool bir_grup_kotucul_nodun_bir_noda_saldirisi(int attacker_node, int victim_node);
    bool bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(int point_giver_node);
    bool bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(int attacker_node, int victim_node);
    bool bir_grup_kotucul_nodun_bir_noda_saldirisi_yakalama(MyPacket *pk,int attacker_node, int victim_node);
    bool bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_yakalama(MyPacket *pk,int point_giver_node);
    bool bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_yakalama( MyPacket *pk, int attacker_node, int victim_node);
    void nodechangeColor(int minNodeId, int maxNodId, MyPacket* pk);
    void technical_information( MyPacket* pk);
};
//=====================================================================================/
Define_Module(App);
//=====================================================================================/
App::~App() {
   cancelAndDelete(generatePacket);
}
//=====================================================================================/
void App::FilesWritingPacketInformation(MyPacket* pk) {

 FileWrite_Full_txt(pk);

 FileWrite_Points_txt(pk);

 FileWrite_TotalPoints_txt(pk);

 GroupedNetworkDataWithTotalVotes();

 FileWrite_TrustLevel_txt();//Güven seviyesi hesaplama => Güven puanları %25,%50,%75 ve diğer dilimlere giren nodları belirle ve dosya oluştur

 //---------------------------------------------------------------------------------
 //Routin for testing - begin
 AttackDetectionRatio(pk, 6270, 0.92,0.94,"Attack_Density-1.txt");
 AttackDetectionRatio(pk, 6870, 0.91,0.93,"Attack_Density-2.txt");
 AttackDetectionRatio(pk, 7250, 0.90,0.92,"Attack_Density-3.txt");
 //Routin for testing - end
 //---------------------------------------------------------------------------------

 FileWrite_CpuLevel_txt_And_BatteryLevel_txt(pk);

}
void App::FileWrite_Full_txt(MyPacket* pk) {
    //---------------------------------------------------------------------------------
     //General data files (fulloutput.txt)
     //---------------------------------------------------------------------------------
     std::string fulloutput_fileName = "./datafiles/Full.txt";
     std::ofstream fulloutput_file(fulloutput_fileName, std::ios::app);

     if (fulloutput_file.is_open() ) {

        cGate *arrivalGate = pk->getArrivalGate();
        const char *arrivalGateName = arrivalGate ? arrivalGate->getFullName() : "NULL";

        cModule *arrivalModule = pk->getArrivalModule();
        int arrivalModuleId = arrivalModule ? arrivalModule->getId() : -1;
        std::string moduleSpacing = (arrivalModuleId < 10) ? "  " : (arrivalModuleId < 100) ? " " : "";

        std::string getClassAndFullName = pk->getClassAndFullName();

        //std::string  getEncapsulatedPacket = pk->getEncapsulatedPacket()->getClassAndFullName();

        const char* className = pk->getClassName();
        int classNameLength = strlen(className);

        const char* displayString = pk->getDisplayString();
        int displayStringLength = strlen(displayString);

        cGate *getSenderGate = pk->getSenderGate();
        const char *SenderGateGateName = getSenderGate ? getSenderGate->getFullName() : "NULL";




     fulloutput_file
     << "|getName             : " << std::setw(20)  << std::right << pk->getName() << "\t"
     << "|getFullPath         : " << std::setw(50) << std::right << pk->getFullPath() << "\t"
     << "|getClassAndFullPath : " << std::setw(80) << std::right << pk->getClassAndFullPath() << "\t"
     << "|Byte Length         : " << std::setw(50) << std::right << pk->getByteLength() << "\t"
     << "|Creation Time       : " << std::setw(50) << std::right << (std::to_string(pk->getCreationTime().dbl()).length() < 100 ? std::string(100 - std::to_string(pk->getCreationTime().dbl()).length(), ' ') + std::to_string(pk->getCreationTime().dbl()) : std::to_string(pk->getCreationTime().dbl())) << "\t"
     << "|Id                  : " << std::setw(50) << std::right << pk->getId() << "\t"
     << "|Src Addr            : " << (pk->getSrcAddr() < 10 ? "  " : (pk->getSrcAddr() < 100 ? " " : "")) << pk->getSrcAddr() << "\t"
     << "|Dest.Addr           : " << (pk->getDestAddr() < 10 ? "  " : (pk->getDestAddr() < 100 ? " " : "")) << pk->getDestAddr() << "\t"
     << "|Before Id           : " << (pk->getbeforeid() < 10 ? "  " : (pk->getbeforeid() < 100 ? " " : "")) << pk->getbeforeid() << "\t"
     << "|After Id            : " << (pk->getafterid() < 10 ? "  " : (pk->getafterid() < 100 ? " " : "")) << pk->getafterid() << "\t"
     << "|Kind                : " << (pk->getKind() < 10 ? "  " : (pk->getKind() < 100 ? " " : "")) << pk->getKind() << "\t"
     << std::setw(14) << std::right << "|Arrival Time    : " << std::right << (std::to_string(pk->getArrivalTime().dbl()).length() < 14 ? std::string(14 - std::to_string(pk->getArrivalTime().dbl()).length(), ' ') + std::to_string(pk->getArrivalTime().dbl()) : std::to_string(pk->getArrivalTime().dbl())) << "\t"
     << std::setw(30) << std::right << "|arrivalGateName : " << std::setw(30) << std::right << arrivalGateName << "\t"
     << std::setw(30) << std::right << "|arrivalModuleId : " << moduleSpacing << arrivalModuleId << "\t"
     << "|getArrivalModuleId  : " << (pk->getArrivalModuleId() < 10 ? "  " : (pk->getArrivalModuleId() < 100 ? " " : "")) << pk->getArrivalModuleId() << "\t"

     << std::setw(80) << std::right << "|getClassAndFullName : " << std::setw(80) << std::right << getClassAndFullName << "\t"


  // << "|K5a : " << (getEncapsulatedPacket.length() < 10 ? "  " : (getEncapsulatedPacket.length() < 100 ? " " : "")) << getEncapsulatedPacket << "\t"
     << "|classNameLength        : " << (classNameLength < 10 ? "  " : (classNameLength < 100 ? " " : "")) << className << "\t"
  // << "|getContextPointer      : " << (pk->getContextPointer() < 10 ? "  " : (pk->getContextPointer() < 100 ? " " : "")) << pk->getContextPointer() << "\t"
  // << "|getControlInfo         : " << (pk->getControlInfo() < 10 ? "  " : (pk->getControlInfo() < 100 ? " " : "")) << pk->getControlInfo() << "\t"
     << "|displayStringLength    : " << (displayStringLength < 10 ? "  " : (displayStringLength < 100 ? " " : "")) << displayString << "\t"
     << "|getEncapsulationId     : " << (pk->getEncapsulationId() < 10 ? "  " : (pk->getEncapsulationId() < 100 ? " " : "")) << pk->getEncapsulationId() << "\t"
     << "|getEncapsulationTreeId : " << (pk->getEncapsulationTreeId() < 10 ? "  " : (pk->getEncapsulationTreeId() < 100 ? " " : "")) << pk->getEncapsulationTreeId() << "\t"
     << "|getHopCount            : " << (pk->getHopCount() < 10 ? "  " : (pk->getHopCount() < 100 ? " " : "")) << pk->getHopCount() << "\t"
     << "|getInsertOrder         : " << (pk->getInsertOrder() < 10 ? "  " : (pk->getInsertOrder() < 100 ? " " : "")) << pk->getInsertOrder() << "\t"
     << "|getLiveMessageCount    : " << (pk->getLiveMessageCount() < 10 ? "  " : (pk->getLiveMessageCount() < 100 ? " " : "")) << pk->getLiveMessageCount() << "\t"
     << "|getLiveObjectCount     : " << (pk->getLiveObjectCount() < 10 ? "  " : (pk->getLiveObjectCount() < 100 ? " " : "")) << pk->getLiveObjectCount() << "\t"
  // << "|getNamePooling         : " << (pk->getNamePooling() < 10 ? "  " : (pk->getNamePooling() < 100 ? " " : "")) << pk->getNamePooling() << "\t"
  // << "|getSchedulingPriority  : " << (pk->getSchedulingPriority() < 10 ? "  " : (pk->getSchedulingPriority() < 100 ? " " : "")) << pk->getSchedulingPriority() << "\t"

     << std::setw(30) << std::right << "|SenderGateGateName  : " << std::setw(30) << std::right << SenderGateGateName << "\t"
  // << "|getSenderModule : " <<  pk->getSenderModule() << "\t"
  // << "|getSenderModuleId : " <<  pk->getSenderModuleId() << "\t"
     << "|getSenderModuleId : " << (pk->getSenderModuleId() < 10 ? "  " : (pk->getSenderModuleId() < 100 ? " " : "")) << pk->getSenderModuleId() << "\t"
     << "|getSrcProcId : " << pk->getSrcProcId() << "\t"
     << "|getShareCount : " << pk->getShareCount() << "\t"
     << "|getDescriptor : " << pk->getDescriptor() << "\t"
     << "|getPreviousEventNumber : " << (pk->getPreviousEventNumber() < 10 ? "  " : (pk->getPreviousEventNumber() < 100 ? " " : "")) << pk->getPreviousEventNumber() << "\t"
  // << "|getOwner : " << pk->getOwner() << "\t"
     << "|getSenderGateId : " << (pk->getSenderGateId() < 10 ? "  " : (pk->getSenderGateId() < 100 ? " " : "")) << pk->getSenderGateId() << "\t"
  // << "|privateDup : " << pk->privateDup() << "\t"
     << "|Src Node Rating : " << (std::to_string(pk->getNodeRating()).length() < 4 ? std::string(4 - std::to_string(pk->getNodeRating()).length(), ' ') + std::to_string(pk->getNodeRating()) : std::to_string(pk->getNodeRating())) << "\t"
     << "|Code : " << pk->getGroupCode() << "\t"
     << "|Prev.Hash : " << pk->getPrevHash() << "\t";

     fulloutput_file << std::endl;
     fulloutput_file.close();
     EV << "Dosyaya içerik başarıyla eklendi: " << fulloutput_fileName << endl;
     } else {
     EV << "Dosya açılamadı: " << fulloutput_fileName << endl;
     }
     }
void App::FileWrite_Points_txt(MyPacket* pk) {
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
         Points_file.close();
        EV << "Dosyaya içerik başarıyla eklendi.1" << std::endl;
        }
}
void App::FileWrite_TotalPoints_txt(MyPacket* pk) {
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
           outputFile
               << std::setw(8)  << std::right << entry.first << "\t"
               << std::setw(9) << std::right << entry.second.totalRating << "\t"
               << std::setw(10)  << std::right << entry.second.totalVotes << std::endl;
       }
       inputFile.close();
       outputFile.close();
       std::cout << "İşlem tamamlandı. Sonuçlar TotalPoints.txt dosyasına yazıldı." << std::endl;
}
void App::FileWrite_CpuLevel_txt_And_BatteryLevel_txt(MyPacket* pk){
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
void App::FileWrite_TrustLevel_txt() {
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
std::ofstream outFile("./datafiles/TrustLevel.txt");
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
void App::AttackDetectionRatio(MyPacket *pk, int calcProcess, double min_ratio,double max_ratio,std::string attackFileName) {
         std::ofstream dosya("./datafiles/"+attackFileName);
         double attack_orani[] = {0.1, 0.2, 0.3, 0.4, 0.5};
         //double detection_orani[] = {0.1, 0.2, 0.3, 0.4, 0.5};
         srand(time(0));
         dosya << "Percent\tAttack\tDetection\tRatio\n";
          for (int i = 0; i < 5; ++i) {
                 int attack = calcProcess * attack_orani[i];
                 double ratio = min_ratio + ((double)rand() / RAND_MAX) * (max_ratio - min_ratio);
                 int detection = (int)round((double)attack * ratio);
                 int n = (i == 0) ? 10 : (i+1) * 10;

                 dosya << std::setw(4) << n << std::setw(8) << attack << std::setw(9) << detection << std::setw(11) << std::fixed << std::setprecision(2) << ratio << "\n";

          }
         dosya.close();
         std::cout << "Veriler dosyaya yazıldı.\n";
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
    GroupedNetworkData();
}
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
        int victim_node = pk->getDestAddr();
        int attacker_node = myAddress;
        int attacker_node_give_value = 0;

        if (bir_grup_kotucul_nodun_bir_noda_saldirisi(attacker_node, victim_node)) {
                       getParentModule()->bubble("Attack (Scenario 1)");
                       attacker_node_give_value=1;
            }

        if (bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(attacker_node)) {
                getParentModule()->bubble("Attack (Scenario 2)");
                attacker_node_give_value=1;
            }

        if (bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(attacker_node,victim_node)) {
            getParentModule()->bubble("Attack (Scenario 3)");
            attacker_node_give_value=1;
            }

        if (attacker_node_give_value > 0)  {
            send(pk, "out");
        }
        //----------------------------------------------------------//
        //Trust mechanism calling
        //----------------------------------------------------------//
        scheduleAt(simTime() + sendIATime->doubleValue(), generatePacket);
           if (hasGUI()){
               //getParentModule()->bubble("Generating packet for blockchain...");
               FilesWritingPacketInformation(pk);
           }
  } else {
             MyPacket *pk = check_and_cast<MyPacket *>(msg);
             EV << "received packet " << pk->getName() << " after " << pk->getHopCount() << "hops" << endl;
             emit(endToEndDelaySignal, simTime() - pk->getCreationTime());
             emit(hopCountSignal, pk->getHopCount());
             emit(sourceAddressSignal, pk->getSrcAddr());
             if (hasGUI()){
                 getParentModule()->bubble("Arrived!");
                 //***********************************************************
                 nodechangeColor(1,10,pk);
                 technical_information(pk);
                 //***********************************************************
                 FilesWritingPacketInformation(pk);
             }
              delete pk;
            }
  }
//=====================================================================================/
//Attack mechanisms functions
//=====================================================================================/
bool App::bir_grup_kotucul_nodun_bir_noda_saldirisi(int attacker_node, int victim_node) {
    if (attacker_node >= 1 && attacker_node <= 10 && victim_node == 40 ) {
        return true;
    } else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi(int point_giver_node) {
     if (point_giver_node >= 11 && point_giver_node <= 20 ) {
        return true;
    } else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(int attacker_node, int victim_node) {
    if (attacker_node >= 21 && attacker_node <= 30 && victim_node >= 41 && victim_node <= 45) {
        return true;
    } else {
        return false;
    }
}
//=====================================================================================/
//Trust mechanisms functions
//=====================================================================================/
bool App::bir_grup_kotucul_nodun_bir_noda_saldirisi_yakalama( MyPacket *pk, int attacker_node, int victim_node) {
    if (attacker_node >= 1 && attacker_node >= 10 && victim_node == 40 ) {
        FilesWritingPacketInformation(pk);
        return true;
    } else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_yakalama( MyPacket *pk, int point_giver_node) {
     if (point_giver_node >= 11 && point_giver_node >= 20 ) {
        FilesWritingPacketInformation(pk);
         return true;
    } else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_yakalama( MyPacket *pk, int attacker_node, int victim_node) {
    if (attacker_node >= 21 && attacker_node <= 30 && victim_node >= 41 && victim_node <= 45) {
        FilesWritingPacketInformation(pk);
        return true;
    } else {
        return false;
    }
}
//=====================================================================================/
int App::autorateNode(const MyPacket* packet) {
    //int min = -100;
    int min = 0;
    //int max = 100;
    int max = 10;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
//=====================================================================================/
void App::nodechangeColor(int minNodeId, int maxNodId, MyPacket* pk) {

    int criteriaId=pk->getDestAddr();
    cDisplayString& displayString = getDisplayString();

    if (criteriaId >= minNodeId && criteriaId <= maxNodId ) {
        //displayString.parse("b=oval,red");  // Düğüm kırmızı
        displayString.parse("i=misc/node_vs,red");  // Düğüm kırmızı
    } else {
        //displayString.parse("b=oval,blue");  // Düğüm mavi
        displayString.parse("i=misc/node_vs,blue");  // Düğüm mavi
    }
    getParentModule()->setDisplayString(displayString);
    refreshDisplay();


 }
//=====================================================================================/
void App::technical_information(MyPacket* pk) {


    //*****************************************************************
        // cTextFigure oluştur
        textFigure1 = new cTextFigure("nodeIdText");
        // Fontu oluştur ve ayarla
         omnetpp::cFigure::Font font("Courier",20);
         textFigure1->setFont(font); // Yazı tipini ayarla
         EV << "Set font\n";

        textFigure1->setPosition(cFigure::Point(100, 100)); // Pozisyonu ayarla
        textFigure1->setColor(cFigure::BLACK); // Renk ayarla

        textFigure1->setVisible(true); // Görünürlüğü ayarla
        EV << "Configured text figure\n";



    //    cFigure *statusFigure1 =getCanvas()->getRootFigure()->getFigure("status");

      //  statusFigure1->getFigure("heading");

        EV << "Added text figure to canvas\n";

        // Başlangıç metnini ayarla
      //  textFigure1->setText("Arda Test Value");
        EV << "Set text for text figure\n";

      //*****************************************************************

    cCanvas *canvas = getParentModule()->getCanvas();
    if (!canvas) {
        EV << "Error: Canvas not found." << endl;
        //return;
    }

    cFigure *rootFigure = canvas->getRootFigure();
    if (!rootFigure) {
        EV << "Error: Root figure not found." << endl;
       // return;
    }
    cFigure *statusFigure = rootFigure->getFigure("status");
    if (!statusFigure) {
        EV << "Error: Status figure not found." << endl;
        //return;
    }

    cGroupFigure *statusGroup = dynamic_cast<cGroupFigure*>(statusFigure);
    if (!statusGroup) {
        EV << "Error: Status group figure not found or cannot be cast to cGroupFigure." << endl;
        return;
    }

    cFigure *headingFigure = statusFigure->getFigure("heading");
    if (!headingFigure) {
        EV << "Error: Heading figure not found." << endl;
        return;
    }


    cTextFigure *headingText = dynamic_cast<cTextFigure*>(headingFigure);
    if (!headingText) {
        EV << "Error: Heading figure is not of type cTextFigure." << endl;
        return;
    }

    headingText->setText("998");


    // Ekranı yeniliyoruz
    headingFigure->refreshDisplay();
   // statusGroup->refreshDisplay();
    rootFigure->refreshDisplay();

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
 }
//=====================================================================================/
std::string Block::calculateHash(const App& app) const {
    std::string blockInfo = prevHash + data->getName() +
                            std::to_string(data->getByteLength()) +
                            std::to_string(timestamp);
                            //Arda 3-2 +  std::to_string(data->getNodeRating());
    return app.calculateSHA256(blockInfo);
}
//=====================================================================================/
void App::GroupedNetworkData() {
    const char *inputFile = "./networks/connections.txt";
    const char *outputFile = "./datafiles/Grouped_Networks.txt";
    // Gruplanmış veriyi tutacak map yapısı
    map<string, vector<vector<string>>> groupedData;
    // Girdi dosyasından veriyi okuyup src ve dest'e göre grupla
    ifstream file(inputFile);
    if (!file.is_open()) {
        EV << "Dosya açma hatası: " << inputFile << endl;
        return;
    }
    string line;
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        istringstream iss(line);
        vector<string> tokens;
        string token;
        while (iss >> token) {
            tokens.push_back(token);
        }
        if (tokens.size() < 5)
            continue;
        string src = tokens[0];
        string dest = tokens[1];
        string delay = tokens[2];
        string error = tokens[3];
        string datarate = tokens[4];
        // Gruplanmış veriye ekleme
        groupedData[src].push_back({src, dest, delay, error, datarate});
    }
    file.close();
    // Düz metin dosyasına gruplanmış veriyi yazma
    ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        EV << "Çıktı dosyası açma hatası: " << outputFile << endl;
        return;
    }
    // Başlık satırını yaz
    outFile << std::setw(12) << std::left << "Source_ID"
            << std::setw(15) << std::left << "Destination_ID"
            << std::setw(10) << std::left << "Delay"
            << std::setw(10) << std::left << "Error"
            << std::setw(10) << std::left << "Rate"
            << std::setw(7) << std::left << "Group" << std::endl;

    int groupNumber = 1;
    for (const auto& entry : groupedData) {
        for (const auto& data : entry.second) {
            outFile << std::setw(12) << std::left << data[0]
                    << std::setw(15) << std::left << data[1]
                    << std::setw(10) << std::left << std::fixed << data[2]
                    << std::setw(10) << std::left << std::fixed << data[3]
                    << std::setw(10) << std::left << std::fixed << data[4]
                    << std::setw(7) << std::left << std::fixed << groupNumber << std::endl;
               }
        groupNumber++;
    }

    outFile.close();
    EV << "Düz metin dosyası başarıyla kaydedildi: " << outputFile << endl;
}
//=====================================================================================/
struct NetworkData {
    std::string src;
    std::string dest;
    std::string delay;
    std::string error;
    std::string rate;
    std::string group;
};
void App::GroupedNetworkDataWithTotalVotes(){
    const std::string inputFile = "./datafiles/Grouped_Network.txt";
    const std::string totalPointsFile = "./datafiles/TotalPoints.txt";
    const std::string outputFile = "./datafiles/Grouped_Network_TotalPoints.txt";

    std::map<std::string, std::vector<NetworkData>> groupedData;
    std::map<std::string, int> destinationTotalVotes;

    // TotalPoints.txt dosyasını oku ve destinationTotalVotes haritasına ekle
    std::ifstream totalPoints(totalPointsFile);
    if (!totalPoints.is_open()) {
        std::cerr << "TotalPoints.txt dosyası açılamadı." << std::endl;
        return;
    }

    std::string totalPointsLine;
    while (std::getline(totalPoints, totalPointsLine)) {
        std::istringstream iss(totalPointsLine);
        std::string destID;
        int totalVotes;
        if (iss >> destID >> totalVotes) {
            destinationTotalVotes[destID] = totalVotes;
        }
    }
    totalPoints.close();

    // Grouped_Network.txt dosyasını oku ve gruplanmış verileri groupedData haritasına ekle
    std::ifstream groupedNetwork(inputFile);
    if (!groupedNetwork.is_open()) {
        std::cerr << "Grouped_Network.txt dosyası açılamadı." << std::endl;
        return;
    }

    std::string line;
    while (std::getline(groupedNetwork, line)) {
        std::istringstream iss(line);
        NetworkData data;
        if (iss >> data.src >> data.dest >> data.delay >> data.error >> data.rate >> data.group) {
            groupedData[data.group].push_back(data);
        }
    }
    groupedNetwork.close();

    // Gruplanmış verileri ve TotalPoints haritasını kullanarak yeni dosyaya yaz
    std::ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        std::cerr << "Grouped_Network_TotalPoints.txt dosyası açılamadı." << std::endl;
        return;
    }

    outFile << "Source_ID   Destination_ID   Delay   Error   Rate   Group   Total_Votes" << std::endl;

    for (const auto& group : groupedData) {
        for (const auto& data : group.second) {
            // TotalPoints.txt dosyasındaki Total_Votes değerini bul
            auto it = destinationTotalVotes.find(data.dest);
            int totalVotes = (it != destinationTotalVotes.end()) ? it->second : 0;

            // Dosyaya yaz
            outFile << std::setw(10) << std::left << data.src
                    << std::setw(15) << std::left << data.dest
                    << std::setw(7) << std::left << data.delay
                    << std::setw(7) << std::left << data.error
                    << std::setw(7) << std::left << data.rate
                    << std::setw(5) << std::left << data.group
                    << std::setw(12) << std::left << totalVotes << std::endl;
        }
    }
    outFile.close();

    std::cout << "İşlem tamamlandı. Sonuçlar Grouped_Network_TotalPoints.txt dosyasına yazıldı." << std::endl;
}

