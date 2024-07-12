#ifdef _MSC_VER
#pragma warning(disable:4786)
#endif
//=====================================================================================/
//Include files =======================================================================/
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
#include <filesystem>
#include <locale>
#include <codecvt>
#include <thread>
#include <unordered_map>
#include <vector>
#include <map>
#include <string>
#include "/home/asus/Desktop/omnetpp-6.0.3/include/tinyxml2/tinyxml2.h"
//=====================================================================================/
using namespace omnetpp;
using namespace std;
//=====================================================================================/
int mfieldnames;
std::string bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_dosya_tipi = "30"; //Burada yazılan değer saldırı % ve saldırgan sayısını belirler.
//=====================================================================================/
class App;
//=====================================================================================/
class MyPacket : public Packet
{
private:
    std::string prevHash;
    int nodeRating;
    std::string groupCode;
    int beforeid = 0;
    int afterid = 0;
public:
    MyPacket(const char *name = nullptr, int kind = 0) :
            Packet(name, kind)
    {
    }
    const std::string& getPrevHash() const
    {
        return prevHash;
    }
    void setPrevHash(const std::string &prevHash)
    {
        this->prevHash = prevHash;
    }
    int getNodeRating() const
    {
        return nodeRating;
    }
    void setNodeRating(int rating)
    {
        this->nodeRating = rating;
    }
    const std::string& getGroupCode() const
    {
        return groupCode;
    }
    void setGroupCode(const std::string &code)
    {
        this->groupCode = code;
    }
    int getbeforeid() const
    {
        return beforeid;
    }
    void setbeforeid(int beforeid)
    {
        this->beforeid = beforeid;
    }
    int getafterid() const
    {
        return afterid;
    }
    void setafterid(int afterid)
    {
        this->afterid = afterid;
    }
};
//=====================================================================================/
class Block
{
private:
    std::string hash;
    std::string prevHash;
    MyPacket *data;
    time_t timestamp;
    int nodeRating;
public:
    Block(MyPacket *data, const std::string &prevHash);
    std::string calculateHash(const App &app) const;
    std::string getHash() const
    {
        return hash;
    }
    std::string getPrevHash() const
    {
        return prevHash;
    }
};
//=====================================================================================/
class App : public cSimpleModule
{
private:
    cTextFigure *textFigure1;
    std::map<int, int> nodeRatings;
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
//---------------------------------------------------/
    void FilesWritingPacketInformation(MyPacket *pk);
    void FileWrite_Full_txt(MyPacket *pk);
    void FileWrite_Points_txt(MyPacket *pk);
    void FileWrite_TotalPoints_txt(MyPacket *pk);
    void FileWrite_Attacks_txt(MyPacket *pk);
    void FileWrite_TrustLevel_txt();
    void FileWrite_CpuLevel_txt_And_BatteryLevel_txt(MyPacket *pk);
    void AttackDetectionRatio(MyPacket *pk, int calcProcess, double min_ratio, double max_ratio, std::string attackFileName);
    void Write_Content_to_All_Nodes_Txt(const std::string &SourceFile, int NodeCount);
    void GroupedNetworkData_Txt();
    void Grouped_Network_TotalPoints_Xml();
    void Nodes_Network_TotalPoints_Xml();
    void GroupedNetworkDataWithGroupTotalsPoints_Xml();
    void All_Network_TotalPoints_Xml();
    void MergeXmlFiles();
    void Detection_of_good_and_malicious_nodes_Xml();
    void Calculate_of_EWMA_Formulas_Xml();
    void Write_Transactions_to_All_Nodes_Xml(MyPacket *pk);
//---------------------------------------------------/
public:
    virtual ~App();
    std::string calculateSHA256(const std::string &input) const;
//---------------------------------------------------/
    std::string padStringStr(const std::string &str, size_t length)
    {
        if (str.length() < length) {
            return str + std::string(length - str.length(), ' ');
        }
        return str;
    }
    std::string padStringInt(int value, size_t length)
    {
        std::ostringstream oss;
        oss << value;
        return padStringStr(oss.str(), length);
    }
    std::string padStringDouble(double value, size_t length)
    {
        std::ostringstream oss;
        oss << value;
        return padStringStr(oss.str(), length);
    }
//---------------------------------------------------/
    void delete_xml_txt_Files()
    {
        namespace fs = std::filesystem;
        std::string dosya_tipi =
                bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_dosya_tipi;

        std::string directory = "./datafiles/";
        std::set<std::string> filesToExclude;

        if (dosya_tipi == "30") {
            filesToExclude = { "Ewma_Data_With_Attack_A1-40.xml", "Ewma_Data_With_Attack_A1-50.xml",
                    "Ewma_Data_With_Attack_A1-60.xml", "Ewma_Data_With_Attack_A1-70.xml" };
        }
        else if (dosya_tipi == "40") {
            filesToExclude = { "Ewma_Data_With_Attack_A1-30.xml", "Ewma_Data_With_Attack_A1-50.xml",
                    "Ewma_Data_With_Attack_A1-60.xml", "Ewma_Data_With_Attack_A1-70.xml" };
        }
        else if (dosya_tipi == "50") {
            filesToExclude = { "Ewma_Data_With_Attack_A1-30.xml", "Ewma_Data_With_Attack_A1-40.xml",
                    "Ewma_Data_With_Attack_A1-60.xml", "Ewma_Data_With_Attack_A1-70.xml" };
        }
        else if (dosya_tipi == "60") {
            filesToExclude = { "Ewma_Data_With_Attack_A1-30.xml", "Ewma_Data_With_Attack_A1-40.xml",
                    "Ewma_Data_With_Attack_A1-50.xml", "Ewma_Data_With_Attack_A1-70.xml" };
        }
        else if (dosya_tipi == "70") {
            filesToExclude = { "Ewma_Data_With_Attack_A1-30.xml", "Ewma_Data_With_Attack_A1-40.xml",
                    "Ewma_Data_With_Attack_A1-50.xml", "Ewma_Data_With_Attack_A1-60.xml" };
        }

        for (const auto &entry : fs::directory_iterator(directory)) {
            std::string extension = entry.path().extension().string();
            std::string filename = entry.path().filename().string();

            if ((extension == ".xml" || extension == ".txt") && filesToExclude.find(filename) == filesToExclude.end()) {
                fs::remove(entry.path());
                std::cout << "Deleted: " << entry.path() << std::endl;
            }
        }
    }
//---------------------------------------------------/
protected:
    virtual void initialize() override;
    void handleMessage(cMessage *msg) override;
    std::string calculateHash(const MyPacket *packet);

    int autorateNode(int attacker_node_Src, int attacker_node_Dest, MyPacket *pk);

    int bir_grup_kotucul_nodun_bir_noda_saldirisi_autorateNode(const MyPacket *packet);
    int bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_autorateNode(const MyPacket *packet);
    bool bir_grup_kotucul_nodun_bir_noda_saldirisi(int attacker_node, int victim_node);
    bool bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi(int point_giver_node);
    bool bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(int attacker_node, int victim_node);
    bool bir_grup_kotucul_nodun_bir_noda_saldirisi_yakalama(MyPacket *pk, int attacker_node, int victim_node);
    void bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_yakalama(int puan_veren_node_id, int puan_alan_node_id);
    bool bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_yakalama(MyPacket *pk, int attacker_node, int victim_node);

    void nodechangeColor_Red();
    void nodechangeColor_Blue();
    void technical_information(MyPacket *pk);
};
//=====================================================================================/
Define_Module(App);
//=====================================================================================/
App::~App()
{
    cancelAndDelete(generatePacket);
}
//=====================================================================================/
//Txt Files ===========================================================================/
//=====================================================================================/
void App::FilesWritingPacketInformation(MyPacket *pk)
{
    // Paketin tam bilgilerini bir metin dosyasına yaz
    FileWrite_Full_txt(pk);
    // Paketin puan bilgilerini bir metin dosyasına yaz
    FileWrite_Points_txt(pk);
    // Tüm düğümlere ait işlem bilgilerini bir XML dosyasına yaz
    Write_Transactions_to_All_Nodes_Xml(pk);
    // Toplam puan bilgilerini bir metin dosyasına yaz
    FileWrite_TotalPoints_txt(pk);
    // Saldırı bilgilerini bir metin dosyasına yaz
    FileWrite_Attacks_txt(pk);
    // Gruplanmış ağ toplam puan bilgilerini bir XML dosyasına yaz
    Grouped_Network_TotalPoints_Xml();
    // Düğümlerin ağ toplam puan bilgilerini bir XML dosyasına yaz
    Nodes_Network_TotalPoints_Xml();
    // Gruplanmış ağ verilerini toplam puanlarla birlikte bir XML dosyasına yaz
    GroupedNetworkDataWithGroupTotalsPoints_Xml();
    // Tüm ağın toplam puan bilgilerini bir XML dosyasına yaz
    All_Network_TotalPoints_Xml();
    // XML dosyalarını birleştir
    MergeXmlFiles();
    // İyi ve kötü niyetli düğümlerin tespitini yap ve bir XML dosyasına yaz
    Detection_of_good_and_malicious_nodes_Xml();
    // EWMA formüllerini hesapla ve bir XML dosyasına yaz
    Calculate_of_EWMA_Formulas_Xml();
    // Bir grup kötü niyetli düğümün birbirlerine yüksek puan verme saldırısını yakala
    bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_yakalama(pk->getSrcAddr(),
            pk->getDestAddr());
    // Güven seviyesi bilgilerini bir metin dosyasına yaz
    FileWrite_TrustLevel_txt();
    // CPU seviyesi ve batarya seviyesi bilgilerini bir metin dosyasına yaz
    FileWrite_CpuLevel_txt_And_BatteryLevel_txt(pk);
}
void App::FileWrite_Full_txt(MyPacket *pk)
{
    std::string fulloutput_fileName = "./datafiles/Full.txt";
    std::ofstream fulloutput_file(fulloutput_fileName, std::ios::app);
    if (fulloutput_file.is_open()) {
//---------------------------------------------------/
        std::stringstream fulloutput;
        fulloutput
        /*
         << "|getId : " <<std::left << padStringInt(pk->getId(),7) << "\t"
         << "|getName : " << std::left << padStringStr(pk->getName(),15) << "\t"
         << "|getFullPath : " << std::left << padStringStr(pk->getFullPath(), 45) << "\t"
         << "|getClassAndFullPath : " << std::left << padStringStr(pk->getClassAndFullPath(), 55) << "\t"
         << "|getClassAndFullName : " << std::left << padStringStr(pk->getClassAndFullName(),25) << "\t"
         << "|getOwner->getFullName : " << std::left << padStringStr(pk->getOwner()->getFullName(),20) << "\t"
         << "|getByteLength : " << std::left << padStringInt(pk->getByteLength(),5) << "\t"
         << "|getTotalObjectCount : " << std::left << padStringInt(pk->getTotalObjectCount(),7) << "\t"
         */
        << "|getCreationTime " << std::left << padStringDouble(pk->getCreationTime().dbl(), 15) << "\t"
                << "|getArrivalTime " << std::left << padStringDouble(pk->getArrivalTime().dbl(), 15) << "\t"
                /*
                 << "|arrivalGateName->getFullName : " << std::left << padStringStr(pk->getArrivalGate() ? pk->getArrivalGate()->getFullName() : "NULL",10) << "\t"
                 << "|arrivalModuleId->getId : " << std::left << padStringInt( pk->getArrivalModule() ? pk->getArrivalModule()->getId() : -1, 7) << "\t"
                 << "|getArrivalModuleId : " << std::left << padStringInt(pk->getArrivalModuleId(),7) << "\t"
                 << "|getSenderModuleId : " << std::left << padStringInt(pk->getSenderModuleId(),7) << "\t"
                 << "|getSenderGateId : " << std::left << padStringInt(pk->getSenderGateId(),7) << "\t"
                 << "|getDescriptor->getFullPath : " << std::left << padStringStr(pk->getDescriptor()->getFullPath() ,7) << "\t"
                 << "|getSendingTime : " << std::left << padStringDouble(pk->getSendingTime().dbl(),15) << "\t"
                 << "|getEncapsulationId : " << std::left << padStringInt(pk->getEncapsulationId(),7) << "\t"
                 << "|getEncapsulationTreeId : " << std::left << padStringInt(pk->getEncapsulationTreeId(),7) << "\t"
                 << "|getHopCount : " << std::left << padStringInt(pk->getHopCount(),7) << "\t"
                 << "|getInsertOrder : " << std::left << padStringInt(pk->getInsertOrder(),7) << "\t"
                 << "|getLiveMessageCount : " << std::left << padStringInt(pk->getLiveMessageCount(),7) << "\t"
                 << "|getLiveObjectCount : " << std::left << padStringInt(pk->getLiveObjectCount(),7) << "\t"
                 << "|getShareCount : " << std::left << padStringInt(pk->getShareCount(),7) << "\t"
                 << "|getDescriptor->getFullName : " << std::left << padStringStr(pk->getDescriptor()->getFullName(),15) << "\t"
                 << "|getPreviousEventNumber : " << std::left << padStringInt(pk->getPreviousEventNumber(),7) << "\t"
                 << "|getKind : " << std::left << padStringInt(pk->getKind(),7) << "\t"
                 */
                << "|getDestAddr " << std::left << padStringInt(pk->getDestAddr(), 7) << "\t"
                /*
                 << "|getbeforeid : " << std::left << padStringInt(pk->getbeforeid(),7) << "\t"
                 << "|getafterid : " << std::left << padStringInt(pk->getafterid(),7) << "\t"
                 */
                << "|getSrcAddr " << std::left << padStringInt(pk->getSrcAddr(), 7) << "\t"
                /*
                 << "|getSrcProcId : " << std::left << padStringInt(pk->getSrcProcId(),7) << "\t"
                 << "|getGroupCode(Src) : " << std::left << padStringStr(pk->getGroupCode(),7) << "\t"
                 */
                << "|getNodeRating " << std::left << padStringInt(pk->getNodeRating(), 7) << "\t" << "|getPrevHash "
                << std::left << padStringStr(pk->getPrevHash(), 100) << "\t";
        fulloutput << std::endl;
        fulloutput_file << fulloutput.str();
        fulloutput_file.close();
//---------------------------------------------------/
        Write_Content_to_All_Nodes_Txt(fulloutput_fileName, 54);
//---------------------------------------------------/
        EV << "Dosyaya içerik başarıyla eklendi: " << fulloutput_fileName << endl;
    }
    else {
        EV << "Dosya açılamadı: " << fulloutput_fileName << endl;
    }
}
void App::FileWrite_Points_txt(MyPacket *pk)
{
    std::string PointsfileName = "./datafiles/Points.txt";
    std::ofstream Points_file(PointsfileName, std::ios::app);
    if (Points_file.is_open() && mfieldnames == 0) {
        Points_file << std::setw(10) << std::left << "Source_ID" << std::setw(15) << std::left << "Destination_ID"
                << std::setw(7) << std::left << "Rating" << std::setw(5) << std::left << "Votes" << std::endl;
        Points_file.close();
        std::cout << "Başlıklar dosyaya yazıldı.1" << std::endl;
    }
    if (Points_file.is_open()) {
        Points_file << std::setw(5) << pk->getbeforeid() << std::setw(13) << pk->getafterid() << std::setw(11)
                << pk->getNodeRating() << std::setw(6) << 1 << std::endl;
        Points_file.close();
        EV << "Dosyaya içerik başarıyla eklendi.1" << std::endl;
    }
}
void App::FileWrite_TotalPoints_txt(MyPacket *pk)
{
    std::string PointsTotalfileName = "./datafiles/TotalPoints.txt";
    std::ofstream PointsTotal_file(PointsTotalfileName, std::ios::app);
    struct Data
    {
        int totalRating = 0;
        int totalVotes = 0;
    };
    std::ifstream inputFile("./datafiles/Points.txt");
    std::ofstream outputFile("./datafiles/TotalPoints.txt");
    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::cout << "Dosya açılamadı! -1" << std::endl;
        return;
    }
    else {
        outputFile << std::setw(15) << std::left << "Source_ID" << std::setw(13) << std::left << "Total_Rating"
                << std::setw(12) << std::left << "Total_Votes" << std::endl;
    }
    std::unordered_map<int, Data> sourceData;
    std::string line;
    std::getline(inputFile, line);
    while (std::getline(inputFile, line)) {
        std::istringstream iss(line);
        int sourceID, destinationID, rating, votes;
        if (!(iss >> sourceID >> destinationID >> rating >> votes)) {
            std::cout << "Veri okunamadı!" << std::endl;
            continue;
        }
        sourceData[sourceID].totalRating += rating;
        sourceData[sourceID].totalVotes += votes;
    }
    for (const auto &entry : sourceData) {
        outputFile << std::setw(8) << std::right << entry.first << "\t" << std::setw(9) << std::right
                << entry.second.totalRating << "\t" << std::setw(10) << std::right << entry.second.totalVotes
                << std::endl;
    }
    inputFile.close();
    outputFile.close();
    std::cout << "İşlem tamamlandı. Sonuçlar TotalPoints.txt dosyasına yazıldı." << std::endl;
}
void App::FileWrite_Attacks_txt(MyPacket *pk)
{
    std::string PointsfileName = "./datafiles/Attacks.txt";
    std::ofstream Points_file(PointsfileName, std::ios::app);
    if (Points_file.is_open() && mfieldnames == 0) {
        Points_file << std::setw(10) << std::left << "Source_ID" << std::setw(15) << std::left << "Destination_ID"

        << std::setw(7) << std::left << "Rating" << std::setw(5) << std::left << "Votes" << std::setw(5) << std::left
                << "Code" << std::endl;
        Points_file.close();
        std::cout << "Başlıklar dosyaya yazıldı.1" << std::endl;
    }
    if (Points_file.is_open()) {
        Points_file << std::setw(5) << pk->getbeforeid() << std::setw(13) << pk->getafterid() << std::setw(11)

        << pk->getNodeRating() << std::setw(6) << 1 << std::left << padStringStr(pk->getGroupCode(), 7) << std::endl;

        Points_file.close();
        EV << "Dosyaya içerik başarıyla eklendi.1" << std::endl;
    }
}
void App::FileWrite_CpuLevel_txt_And_BatteryLevel_txt(MyPacket *pk)
{
//---------------------------------------------------------------------------------
//Calculate for Battery Consumption, CPU Usage - Begin
//---------------------------------------------------------------------------------
//Parameteters
    double toplamIslemSayisi = static_cast<double>(rand()) / RAND_MAX * (100.0 - 1.0);
    double islemParcacigiBoyutu = 200.0;    //byte
    islemParcacigiBoyutu = islemParcacigiBoyutu;    //To avoid unused warning messages during compilation
    double islemBasinaKullanilanCpuYuzdesi = 0.00625;    //%
    double islemBasinaGecenSure = 0.1;    //saniye (100 ms)
    int pilKapasitesi = 20000;    //mAh
    int pilVoltaji = 5;    //V (Volt)
//----
    int toplamIslemSayisi_int = static_cast<int>(round(toplamIslemSayisi));
    double baslangicCpuYuzdesi = 100;    //%
    double toplamkullanılanCpuYuzdesi = (toplamIslemSayisi * islemBasinaKullanilanCpuYuzdesi) * 100;
    double kalanCpuYuzdesi = baslangicCpuYuzdesi - toplamkullanılanCpuYuzdesi;
    kalanCpuYuzdesi = kalanCpuYuzdesi;    //To avoid unused warning messages during compilation
    int pilGucu = (pilVoltaji * pilKapasitesi) / 10000;    //W (Watt)
    double toplamPilGucuTuketimi = (pilGucu * (toplamIslemSayisi * islemBasinaKullanilanCpuYuzdesi)) / 100;    //W
    double toplamEnerjiTuketimiWh = toplamPilGucuTuketimi * (toplamIslemSayisi_int * (islemBasinaGecenSure / 3600)); //Wh
    double toplamEnerjiTuketimimAh = (toplamEnerjiTuketimiWh / toplamPilGucuTuketimi) * 1000;    //mAh
    double toplamEnerjiTuketimiYuzdesi = toplamEnerjiTuketimimAh / pilKapasitesi;    //Wh %
//CPU Usage (CpuLevel.txt)
    std::string CpuLevel_fileName = "./datafiles/CpuLevel.txt";
    std::ofstream CpuLevel_file(CpuLevel_fileName, std::ios::app);
    if (CpuLevel_file.is_open() && mfieldnames == 0) {
        CpuLevel_file << "Node ID\t" << "CPU Usage (%)\t" << "Total number of transactions" << std::endl;
        CpuLevel_file.close();
        std::cout << "Başlıklar dosyaya yazıldı." << std::endl;
    }
    if (CpuLevel_file.is_open()) {
        CpuLevel_file << pk->getafterid() << "\t" << std::fixed << std::setprecision(2) << toplamkullanılanCpuYuzdesi
                << "\t" << std::fixed << std::setprecision(0) << toplamIslemSayisi << "\t";
        CpuLevel_file << std::endl;
        CpuLevel_file.close();
        EV << "Dosyaya içerik başarıyla eklendi: " << CpuLevel_fileName << endl;
    }
//Battery Consumption (BatteryLevel.txt ())
    std::string BatteryLevel_fileName = "./datafiles/BatteryLevel.txt";
    std::ofstream BatteryLevel_file(BatteryLevel_fileName, std::ios::app);

    if (BatteryLevel_file.is_open() && mfieldnames == 0) {
        BatteryLevel_file << "Node ID\t" << "Battery Consumption (%)\t" << "TotalNumber of Transactions" << std::endl;
        BatteryLevel_file.close();
        mfieldnames += 1;
        std::cout << "Başlıklar dosyaya yazıldı." << std::endl;
    }
    if (BatteryLevel_file.is_open()) {
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
        << std::fixed << std::setprecision(8) << std::round(toplamEnerjiTuketimiYuzdesi * 100000000) / 100000000.0
                << "\t" << std::fixed << std::setprecision(0) << toplamIslemSayisi << "\t";
        BatteryLevel_file << std::endl;
        BatteryLevel_file.close();
        EV << "Dosyaya içerik başarıyla eklendi." << std::endl;
    }
//---------------------------------------------------------------------------------
//Calculate for Battery Consumption, CPU Usage - End
//---------------------------------------------------------------------------------
}
void App::FileWrite_TrustLevel_txt()
{
    struct Record
    {
        int Node;
        int Rating;
        int Votes;
        int Serial_no;
        double Percent;
        static bool compareRecords(const Record &a, const Record &b)
        {
            return a.Rating > b.Rating;
        }
    };
//----------------------------------
    std::ifstream inputFile("./datafiles/TotalPoints.txt");
    if (!inputFile.is_open()) {
        std::cout << "Dosya bulunamadı!" << endl;
        return;
    }

    std::vector<Record> records;
    std::string line;

    std::getline(inputFile, line);

    while (std::getline(inputFile, line)) {
        std::istringstream iss(line);
        Record temp;
        if (!(iss >> temp.Node >> temp.Rating >> temp.Votes)) {

            std::cout << "Veri okunamadı!" << std::endl;
            continue;
        }
        records.push_back(temp);

    }
    inputFile.close();
//----------------------------------
    std::sort(records.begin(), records.end(), Record::compareRecords);
//----------------------------------
    double quarter = numNodes * 0.25;
    double half = numNodes * 0.50;
    double three_quarters = numNodes * 0.75;

    for (size_t i = 0; i < records.size(); ++i) {
        records[i].Serial_no = i + 1;
        if (i < quarter) {
            records[i].Percent = 25.0;
        }
        else if (i < half) {
            records[i].Percent = 50.0;
        }
        else if (i < three_quarters) {
            records[i].Percent = 75.0;
        }
        else {
            records[i].Percent = 100.0;
        }
    }
//----------------------------------
    std::ofstream outFile("./datafiles/TrustLevel.txt");
    if (!outFile.is_open()) {
        std::cout << "Çıktı dosyası oluşturulamadı!" << std::endl;
        return;
    }

    outFile << "Node\tRating\tVotes\tSerial_no\tPercent" << std::endl;
    for (const auto &record : records) {

        outFile << std::setw(2) << record.Node << "\t" << std::setw(7) << record.Rating << "\t" << std::setw(7)

        << record.Votes << "\t" << std::setw(9) << record.Serial_no << "\t" << std::setw(8) << record.Percent
                << std::endl;

        std::cout << "Çıktı Trust_Level dosyasına yazdırıldı !" << std::endl;
    }

    std::cout << "Çıktı Trust_Level dosyasına yazdırılması bitti !" << std::endl;
    outFile.close();
//----------------------------------
}
void App::AttackDetectionRatio(MyPacket *pk, int calcProcess, double min_ratio, double max_ratio, std::string attackFileName)
{
    std::ofstream dosya("./datafiles/" + attackFileName);
    double attack_orani[] = { 0.1, 0.2, 0.3, 0.4, 0.5 };
    srand(time(0));
    dosya << "Percent\tAttack\tDetection\tRatio\n";
    for (int i = 0; i < 5; ++i) {
        int attack = calcProcess * attack_orani[i];
        double ratio = min_ratio + ((double) rand() / RAND_MAX) * (max_ratio - min_ratio);
        int detection = (int) round((double) attack * ratio);
        int n = (i == 0) ? 10 : (i + 1) * 10;
        dosya << std::setw(4) << n << std::setw(8) << attack << std::setw(9) << detection << std::setw(11) << std::fixed
                << std::setprecision(2) << ratio << "\n";
    }
    dosya.close();
    std::cout << "Veriler dosyaya yazıldı.\n";
}
void App::Write_Content_to_All_Nodes_Txt(const std::string &SourceFile, int NodeCount)
{
    std::ifstream infile(SourceFile);
    if (!infile.is_open()) {
        std::cerr << "Hata: " << SourceFile << " dosyası açılamadı!" << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << infile.rdbuf();
    std::string Content = buffer.str();
    infile.close();
    for (int i = 1; i <= NodeCount; ++i) {
        std::stringstream filename;
        filename << "./datafiles/" << "Node" << std::setw(2) << std::setfill('0') << i << ".txt";
        std::ofstream outfile(filename.str());
        if (outfile.is_open()) {
            outfile << Content << std::endl;
            outfile.close();
            std::cout << "Node " << i << " dosyası oluşturuldu: " << filename.str() << std::endl;
        }
        else {
            std::cerr << "Hata: " << filename.str() << " dosyası oluşturulamadı!" << std::endl;
        }
    }
}
void App::GroupedNetworkData_Txt()
{
    const char *inputFile = "./networks/connections.txt";
    const char *outputFile = "./datafiles/Grouped_Networks.txt";
    map<string, vector<vector<string>>> groupedData;
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

        groupedData[src].push_back( { src, dest, delay, error, datarate });

    }
    file.close();
    ofstream outFile(outputFile);
    if (!outFile.is_open()) {
        EV << "Çıktı dosyası açma hatası: " << outputFile << endl;
        return;
    }
    outFile << std::setw(12) << std::left << "Source_ID" << std::setw(15) << std::left << "Destination_ID"

    << std::setw(10) << std::left << "Delay" << std::setw(10) << std::left << "Error" << std::setw(10) << std::left
            << "Rate" << std::setw(7) << std::left << "Group" << std::endl;
    int groupNumber = 1;
    for (const auto &entry : groupedData) {
        for (const auto &data : entry.second) {
            outFile << std::setw(12) << std::left << data[0] << std::setw(15) << std::left << data[1] << std::setw(10)
                    << std::left << std::fixed << data[2] << std::setw(10) << std::left << std::fixed << data[3]
                    << std::setw(10) << std::left << std::fixed << data[4] << std::setw(7) << std::left << std::fixed
                    << groupNumber << std::endl;
        }
        groupNumber++;
    }
    outFile.close();
    EV << "Düz metin dosyası başarıyla kaydedildi: " << outputFile << endl;
}
//=====================================================================================/
//Xml Files ===========================================================================/
//=====================================================================================
struct NetworkData
{
    std::string src;
    std::string dest;
    std::string delay;
    std::string error;
    std::string rate;
    std::string group;
};
void App::Grouped_Network_TotalPoints_Xml()
{
    const std::string inputFile = "./datafiles/Grouped_Networks.txt";
    const std::string totalPointsFile = "./datafiles/TotalPoints.txt";
    const std::string outputFile = "./datafiles/Grouped_Network_TotalPoints.xml";
    std::map<std::string, std::vector<NetworkData>> groupedData;
    std::map<std::string, int> destinationTotalVotes;
    std::map<std::string, int> destinationTotalRating;
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLNode *pRoot = doc.NewElement("NetworkData");
    doc.InsertFirstChild(pRoot);
    std::ifstream totalPoints(totalPointsFile);
    if (!totalPoints.is_open()) {
        std::cerr << "TotalPoints.txt dosyası açılamadı." << std::endl;
        return;
    }
    std::string totalPointsLine;
    while (std::getline(totalPoints, totalPointsLine)) {
        std::istringstream iss(totalPointsLine);
        std::string destID;
        int totalVotes, totalRating;
        if (iss >> destID >> totalVotes >> totalRating) {
            destinationTotalVotes[destID] = totalVotes;
            destinationTotalRating[destID] = totalRating;
            std::cerr << ">>>>>>>>>>>>>>>>>>>>>>>>> Grouped_Network_TotalPoints.txt dosyası yazılıyor - 1."
                    << std::endl;
        }
    }
    totalPoints.close();
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
    for (const auto &group : groupedData) {
        for (const auto &data : group.second) {
            auto xit = destinationTotalRating.find(data.dest);
            int totalRating = (xit != destinationTotalRating.end()) ? xit->second : 0;
            auto yit = destinationTotalVotes.find(data.dest);
            int totalVotes = (yit != destinationTotalVotes.end()) ? yit->second : 0;
            double average = (totalVotes != 0) ? static_cast<double>(totalVotes) / totalRating : 0.0;
            tinyxml2::XMLElement *pElement = doc.NewElement("Network");
            pElement->SetAttribute("Source_ID", data.src.c_str());
            pElement->SetAttribute("Destination_ID", data.dest.c_str());
            pElement->SetAttribute("Delay", data.delay.c_str());
            pElement->SetAttribute("Error", data.error.c_str());
            pElement->SetAttribute("Rate", data.rate.c_str());
            pElement->SetAttribute("Group", data.group.c_str());
            pElement->SetAttribute("Total_Votes", totalRating);
            pElement->SetAttribute("Total_Rating", totalVotes);
            pElement->SetAttribute("Average", average);
            pRoot->InsertEndChild(pElement);
            std::cerr << ">>>>>>>>>>>>>>>>>>>>>>>>> Grouped_Network_TotalPoints.txt dosyası yazılıyor - 2."
                    << std::endl;
        }
        std::cerr << ">>>>>>>>>>>>>>>>>>>>>>>>> Grouped_Network_TotalPoints.txt dosyası yazılıyor - 3." << std::endl;
    }
    tinyxml2::XMLError eResult = doc.SaveFile(outputFile.c_str());
    if (eResult != tinyxml2::XML_SUCCESS) {
        std::cerr << "XML dosyası yazılamadı." << std::endl;
        return;
    }
    std::cout << "İşlem tamamlandı. Sonuçlar Grouped_Network_TotalPoints.xml dosyasına yazıldı." << std::endl;
}
void App::Nodes_Network_TotalPoints_Xml()
{
    const std::string inputFile = "./datafiles/Grouped_Networks.txt";
    const std::string totalPointsFile = "./datafiles/TotalPoints.txt";
    const std::string outputFile = "./datafiles/Nodes_Network_TotalPoints.xml";
    std::map<std::string, int> sourceTotalVotes;
    std::map<std::string, int> sourceTotalRating;
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLNode *pRoot = doc.NewElement("NetworkData");
    doc.InsertFirstChild(pRoot);
    std::ifstream totalPoints(totalPointsFile);
    if (!totalPoints.is_open()) {
        std::cerr << "TotalPoints.txt dosyası açılamadı." << std::endl;
        return;
    }
    std::string totalPointsLine;
    while (std::getline(totalPoints, totalPointsLine)) {
        std::istringstream iss(totalPointsLine);
        std::string sourceID;
        int totalVotes, totalRating;

        if (iss >> sourceID >> totalVotes >> totalRating) {
            sourceTotalVotes[sourceID] = totalVotes;
            sourceTotalRating[sourceID] = totalRating;
            std::cerr << ">>>>>>>>>>>>>>>>>>>>>>>>> Grouped_Network_TotalPoints.txt dosyası yazılıyor - 1."
                    << std::endl;
        }
    }
    totalPoints.close();
    std::ifstream groupedNetwork(inputFile);
    if (!groupedNetwork.is_open()) {
        std::cerr << "Grouped_Network.txt dosyası açılamadı." << std::endl;
        return;
    }
    std::map<std::string, std::vector<NetworkData>> groupedData;
    std::string line;
    while (std::getline(groupedNetwork, line)) {
        std::istringstream iss(line);
        NetworkData data;
        if (iss >> data.src >> data.dest >> data.delay >> data.error >> data.rate >> data.group) {
            groupedData[data.src].push_back(data);
        }
    }
    groupedNetwork.close();
    for (const auto &group : groupedData) {
        const std::string &sourceID = group.first;
        int totalVotes = 0;
        int totalRating = 0;
        for (const auto &data : group.second) {
            totalVotes = sourceTotalVotes[data.src];
            totalRating = sourceTotalRating[data.src];
        }
        double average = (totalRating != 0) ? static_cast<double>(totalVotes) / totalRating : 0.0;
        tinyxml2::XMLElement *pElement = doc.NewElement("Network");
        pElement->SetAttribute("Destination_ID", sourceID.c_str());
        pElement->SetAttribute("Total_Votes", totalRating);
        pElement->SetAttribute("Total_Rating", totalVotes);
        pElement->SetAttribute("Average", average);
        pRoot->InsertEndChild(pElement);
        std::cerr << ">>>>>>>>>>>>>>>>>>>>>>>>> Grouped_Network_TotalPoints.txt dosyası yazılıyor - 2." << std::endl;
    }
    tinyxml2::XMLError eResult = doc.SaveFile(outputFile.c_str());
    if (eResult != tinyxml2::XML_SUCCESS) {
        std::cerr << "XML dosyası yazılamadı." << std::endl;
        return;
    }
    std::cout << "İşlem tamamlandı. Sonuçlar Nodes_Network_TotalPoints.xml dosyasına yazıldı." << std::endl;
}
void App::GroupedNetworkDataWithGroupTotalsPoints_Xml()
{
    const std::string inputFile = "./datafiles/Grouped_Networks.txt";
    const std::string totalPointsFile = "./datafiles/TotalPoints.txt";
    const std::string outputFile = "./datafiles/GroupedNetworkDataWithGroupTotalsPoints.xml";
    std::map<std::string, std::vector<NetworkData>> groupedData;
    std::map<std::string, int> destinationTotalVotes;
    std::map<std::string, int> destinationTotalRating;
    std::ifstream totalPoints(totalPointsFile);
    if (!totalPoints.is_open()) {
        std::cerr << "TotalPoints.txt dosyası açılamadı." << std::endl;
        return;
    }
    std::string totalPointsLine;
    while (std::getline(totalPoints, totalPointsLine)) {
        std::istringstream iss(totalPointsLine);
        std::string destID;
        int totalVotes, totalRating;
        if (iss >> destID >> totalVotes >> totalRating) {
            destinationTotalVotes[destID] = totalVotes;
            destinationTotalRating[destID] = totalRating;
        }
    }
    totalPoints.close();
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
    std::map<std::string, int> groupTotalRating;
    std::map<std::string, int> groupTotalVotes;
    for (const auto &group : groupedData) {
        for (const auto &data : group.second) {
            auto xit = destinationTotalRating.find(data.dest);
            int totalRating = (xit != destinationTotalRating.end()) ? xit->second : 0;

            auto yit = destinationTotalVotes.find(data.dest);
            int totalVotes = (yit != destinationTotalVotes.end()) ? yit->second : 0;

            groupTotalRating[group.first] += totalRating;
            groupTotalVotes[group.first] += totalVotes;
        }
    }
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLNode *pRoot = doc.NewElement("NetworkGroups");
    doc.InsertFirstChild(pRoot);
    for (const auto &group : groupTotalRating) {
        std::string groupName = group.first;
        int totalRating = group.second;
        int totalVotes = groupTotalVotes[groupName];
        double average = (totalVotes != 0) ? static_cast<double>(totalVotes) / totalRating : 0.0;
        tinyxml2::XMLElement *pElement = doc.NewElement("Group");
        pElement->SetAttribute("Group_Name", groupName.c_str());
        pElement->SetAttribute("Group_Total_Rating", totalVotes);
        pElement->SetAttribute("Group_Total_Votes", totalRating);
        pElement->SetAttribute("Group_Average", average);
        pRoot->InsertEndChild(pElement);
    }
    tinyxml2::XMLError eResult = doc.SaveFile(outputFile.c_str());
    if (eResult != tinyxml2::XML_SUCCESS) {
        std::cerr << "XML dosyası yazılamadı." << std::endl;
        return;
    }
    std::cout << "İşlem tamamlandı. Sonuçlar Grouped_Network_GrupTotalValues.xml dosyasına yazıldı." << std::endl;
}
void App::All_Network_TotalPoints_Xml()
{
    const std::string inputFile = "./datafiles/Nodes_Network_TotalPoints.xml";
    const std::string outputFile = "./datafiles/All_Network_TotalPoints.xml";

    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(inputFile.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "XML dosyası açılamadı: " << inputFile << std::endl;
        return;
    }

    tinyxml2::XMLElement *pRoot = doc.FirstChildElement("NetworkData");
    if (pRoot == nullptr) {
        std::cerr << "Kök eleman bulunamadı." << std::endl;
        return;
    }

    int totalRatingSum = 0;
    int totalVotesSum = 0;

    for (tinyxml2::XMLElement *pElement = pRoot->FirstChildElement("Network"); pElement != nullptr;
            pElement = pElement->NextSiblingElement("Network")) {
        int totalRating = 0;
        int totalVotes = 0;
        pElement->QueryIntAttribute("Total_Rating", &totalRating);
        pElement->QueryIntAttribute("Total_Votes", &totalVotes);
        totalRatingSum += totalRating;
        totalVotesSum += totalVotes;
    }

    double average = (totalVotesSum != 0) ? static_cast<double>(totalRatingSum) / totalVotesSum : 0.0;

    tinyxml2::XMLDocument newDoc;
    tinyxml2::XMLNode *pNewRoot = newDoc.NewElement("AllTotalPoints");
    newDoc.InsertFirstChild(pNewRoot);

    tinyxml2::XMLElement *pTotalElement = newDoc.NewElement("Total");
    pTotalElement->SetAttribute("Total_Rating", totalRatingSum);
    pTotalElement->SetAttribute("Total_Votes", totalVotesSum);
    pTotalElement->SetAttribute("Average", average);
    pNewRoot->InsertEndChild(pTotalElement);

    tinyxml2::XMLError eResult = newDoc.SaveFile(outputFile.c_str());
    if (eResult != tinyxml2::XML_SUCCESS) {
        std::cerr << "XML dosyası yazılamadı: " << outputFile << std::endl;
        return;
    }

    std::cout << "İşlem tamamlandı. Sonuçlar All_Network_TotalPoints.xml dosyasına yazıldı." << std::endl;
}
void App::MergeXmlFiles()
{
    const std::string inputFile1 = "./datafiles/Grouped_Network_TotalPoints.xml";
    const std::string inputFile2 = "./datafiles/GroupedNetworkDataWithGroupTotalsPoints.xml";
    const std::string inputFile3 = "./datafiles/All_Network_TotalPoints.xml";
    const std::string outputFile = "./datafiles/MergedNetworkData.xml";

    tinyxml2::XMLDocument doc1;
    if (doc1.LoadFile(inputFile1.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "Grouped_Network_TotalPoints.xml dosyası açılamadı." << std::endl;
        return;
    }

    tinyxml2::XMLDocument doc2;
    if (doc2.LoadFile(inputFile2.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "GroupedNetworkDataWithGroupTotalsPoints.xml dosyası açılamadı." << std::endl;
        return;
    }

    tinyxml2::XMLDocument doc3;
    if (doc3.LoadFile(inputFile3.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "All_Network_TotalPoints.xml dosyası açılamadı." << std::endl;
        return;
    }

    tinyxml2::XMLElement *totalElement = doc3.FirstChildElement("AllTotalPoints")->FirstChildElement("Total");
    if (totalElement == nullptr) {
        std::cerr << "Total eleman bulunamadı." << std::endl;
        return;
    }
    int allTotalRating = totalElement->IntAttribute("Total_Rating");
    int allTotalVotes = totalElement->IntAttribute("Total_Votes");
    double allAverage = totalElement->DoubleAttribute("Average");

    std::map<std::string, std::tuple<int, int, double>> groupData;
    tinyxml2::XMLElement *groupElement = doc2.FirstChildElement("NetworkGroups")->FirstChildElement("Group");
    while (groupElement != nullptr) {
        std::string groupName = groupElement->Attribute("Group_Name");
        int groupTotalRating = groupElement->IntAttribute("Group_Total_Rating");
        int groupTotalVotes = groupElement->IntAttribute("Group_Total_Votes");
        double groupAverage = groupElement->DoubleAttribute("Group_Average");
        groupData[groupName] = std::make_tuple(groupTotalRating, groupTotalVotes, groupAverage);
        groupElement = groupElement->NextSiblingElement("Group");
    }

    tinyxml2::XMLElement *networkElement = doc1.FirstChildElement("NetworkData")->FirstChildElement("Network");
    while (networkElement != nullptr) {
        std::string group = networkElement->Attribute("Group");
        if (groupData.find(group) != groupData.end()) {
            auto [groupTotalRating, groupTotalVotes, groupAverage] = groupData[group];
            networkElement->SetAttribute("Group_Total_Rating", groupTotalRating);
            networkElement->SetAttribute("Group_Total_Votes", groupTotalVotes);
            networkElement->SetAttribute("Group_Average", groupAverage);
        }
        networkElement->SetAttribute("All_Total_Rating", allTotalRating);
        networkElement->SetAttribute("All_Total_Votes", allTotalVotes);
        networkElement->SetAttribute("All_Average", allAverage);

        networkElement = networkElement->NextSiblingElement("Network");
    }

    if (doc1.SaveFile(outputFile.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "Yeni XML dosyası yazılamadı." << std::endl;
        return;
    }

    std::cout << "İşlem tamamlandı. Sonuçlar MergedNetworkData.xml dosyasına yazıldı." << std::endl;
}
void App::Detection_of_good_and_malicious_nodes_Xml()
{
    const std::string &inputFile = "./datafiles/MergedNetworkData.xml";
    const std::string &outputFile = "./datafiles/MergedNetworkData_with_Status.xml";

    tinyxml2::XMLDocument doc;
    if (doc.LoadFile(inputFile.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "MergedNetworkData.xml dosyası açılamadı." << std::endl;
        return;
    }

    tinyxml2::XMLElement *networkElement = doc.FirstChildElement("NetworkData")->FirstChildElement("Network");
    while (networkElement != nullptr) {
        double average = networkElement->DoubleAttribute("Average");
        double groupAverage = networkElement->DoubleAttribute("Group_Average");
        double allAverage = networkElement->DoubleAttribute("All_Average");

        std::string status;
        if (average < groupAverage) {
            status = "-1";
        }
        else if (average >= groupAverage && average < allAverage) {
            status = "0";
        }
        else {
            status = "1";
        }

        networkElement->SetAttribute("Status", status.c_str());

        networkElement = networkElement->NextSiblingElement("Network");
    }

    if (doc.SaveFile(outputFile.c_str()) != tinyxml2::XML_SUCCESS) {
        std::cerr << "Yeni XML dosyası yazılamadı." << std::endl;
        return;
    }

    std::cout << "İşlem tamamlandı. Status sütunu MergedNetworkData.xml dosyasına eklendi." << std::endl;
}
void App::Write_Transactions_to_All_Nodes_Xml(MyPacket *pk)
{
    std::string xmlFilePath = "./datafiles/Transactions_to_All_Nodes.xml";
    std::ofstream xmlFile(xmlFilePath, std::ios::app);

    if (xmlFile.is_open() && mfieldnames == 0) {
//---------------------------------------
        xmlFile << "Source_ID=\"" << "\" ";
        xmlFile << "CreationTime=\"" << "\" ";
        xmlFile << "Destination_ID=\"" << "\" ";
        xmlFile << "ArrivalTime=\"" << "\" ";
        xmlFile << "Delay=\"" << "\" ";
        xmlFile << "Rating=\"" << "\" ";
        xmlFile << "Votes=\"" << "\" ";
        xmlFile << "PrevHash=\"" << "<\n";
//---------------------------------------
        if (pk->getbeforeid() <= 54 && pk->getafterid() <= 54) {
//---------------------------------------
            xmlFile << pk->getbeforeid() << "\" ";
            xmlFile << std::left << padStringDouble(pk->getCreationTime().dbl(), 15) << "\" ";
            xmlFile << pk->getafterid() << "\" ";
            xmlFile << std::left << padStringDouble(pk->getArrivalTime().dbl(), 15) << "\" ";
            double creationTime = pk->getCreationTime().dbl();
            double arrivalTime = pk->getArrivalTime().dbl();
            double delay = (arrivalTime > creationTime) ? arrivalTime - creationTime : 0.0;
            xmlFile << std::left << padStringDouble(delay, 15) << "\" ";
            xmlFile << pk->getNodeRating() << "\" ";
            xmlFile << "1\" ";
            xmlFile << std::left << padStringStr(pk->getPrevHash(), 100) << "<\n";
//---------------------------------------
        }
//---------------------------------------
        xmlFile.close();
        std::cout << "XML başlıklar dosyaya yazıldı." << std::endl;
    }

    if (xmlFile.is_open()) {
//---------------------------------------
        if (pk->getbeforeid() <= 54 && pk->getafterid() <= 54) {
//---------------------------------------
            xmlFile << pk->getbeforeid() << "\" ";
            xmlFile << std::left << padStringDouble(pk->getCreationTime().dbl(), 15) << "\" ";
            xmlFile << pk->getafterid() << "\" ";
            xmlFile << std::left << padStringDouble(pk->getArrivalTime().dbl(), 15) << "\" ";
            double creationTime = pk->getCreationTime().dbl();
            double arrivalTime = pk->getArrivalTime().dbl();
            double delay = (arrivalTime > creationTime) ? arrivalTime - creationTime : 0.0;
            xmlFile << std::left << padStringDouble(delay, 15) << "\" ";
            xmlFile << pk->getNodeRating() << "\" ";
            xmlFile << "1\" ";
            xmlFile << std::left << padStringStr(pk->getPrevHash(), 100) << "<\n";
//---------------------------------------
        }
//---------------------------------------
        xmlFile.close();
        std::cout << "XML içerik dosyaya başarıyla eklendi." << std::endl;
    }
}
void App::Calculate_of_EWMA_Formulas_Xml()
{
    const std::string &inputFilePath = "./datafiles/Transactions_to_All_Nodes.xml";
    const std::string &outputFilePath = "./datafiles/Ewma_Data.xml";
    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::cerr << "Dosya açılamadı!" << std::endl;
        return;
    }

//--------------------------------------------------------------------
    double Euler_Degeri = 2.71828; // Sabit
    double Erime_Katsayisi = -0.001; // Sabit
    double Katsayi = 0.5;          // Sabit orjinal hali 0.5
    double Erime_D = 0.9;          //Sabit orjinal hali 0.9
    double Islem_Sayisi = 3.0;     // Değişken
//--------------------------------------------------------------------
    std::map<int, std::vector<std::vector<std::string>>> transactions;
    std::string line;
    while (std::getline(inputFile, line)) {
        if (line.find("Destination_ID") != std::string::npos) {
            continue; // Başlık satırını atla
        }
        std::vector<std::string> tokens;
        size_t pos = 0;
        while ((pos = line.find("\" ")) != std::string::npos) {
            tokens.push_back(line.substr(0, pos));
            line.erase(0, pos + 2);
        }
        tokens.push_back(line); // Son kolonu ekle

        int destId = std::stoi(tokens[2]);
        transactions[destId].push_back(tokens);
    }

    inputFile.close();

    outputFile << "Source_ID,CreationTime,Destination_ID,ArrivalTime,Delay,Rating,Votes,PrevHash,Ewma_Avg\n";

    for (auto &entry : transactions) {
        //int destId = entry.first;
        auto &records = entry.second;
        bool isFirstRecord = true;
        double previousRating = 1.0;

        for (auto &record : records) {
            double rating = std::stod(record[5]);
            if (isFirstRecord) {
                record.push_back(std::to_string(rating));
                previousRating = rating;
                isFirstRecord = false;
            }
            else {
                double Onceki_Puan = previousRating;
                double Erime_D_Formulu = Onceki_Puan * std::pow(Euler_Degeri, Erime_Katsayisi * Islem_Sayisi);
                double Mevcut_Puan = Erime_D_Formulu;
                double Aldigi_Puan = rating;
                double Guncel_Puan_Formulu = (Aldigi_Puan * Katsayi) + ((1 - Katsayi) * Mevcut_Puan * Erime_D);
                double ewmaAvg = Guncel_Puan_Formulu;

                record.push_back(std::to_string(ewmaAvg));
                previousRating = ewmaAvg;
            }

            for (size_t i = 0; i < record.size(); ++i) {
                outputFile << record[i];
                if (i < record.size() - 1) {
                    outputFile << "\" ";
                }
                else {
                    outputFile << "\n";
                }
            }
        }
    }

    outputFile.close();
    std::cout << "EWA hesaplamaları ve XML dosyası başarıyla oluşturuldu." << std::endl;
}
//=====================================================================================/
//System functions ====================================================================/
//=====================================================================================/
void App::initialize()
{
//----------------------------------------------------------//
    App::delete_xml_txt_Files();
//----------------------------------------------------------//
    numNodes = 54;
    myAddress = par("address");
    packetLengthBytes = &par("packetLength");
    sendIATime = &par("sendIaTime");
    pkCounter = 0;
    std::string prevHash = "INITIAL_HASH_VALUE";
    WATCH(pkCounter);
    WATCH(myAddress);
//----------------------------------------------------------//
    const char *destAddressesPar = par("destAddresses");
    cStringTokenizer tokenizer(destAddressesPar);
    const char *token;
    while ((token = tokenizer.nextToken()) != nullptr)
        destAddresses.push_back(atoi(token));
    if (destAddresses.size() == 0)
        throw cRuntimeError("At least one address must be specified in the destAddresses parameter!");
//----------------------------------------------------------//
    generatePacket = new cMessage("nextPacket");
    scheduleAt(sendIATime->doubleValue(), generatePacket);
//----------------------------------------------------------//
    endToEndDelaySignal = registerSignal("endToEndDelay");
    hopCountSignal = registerSignal("hopCount");
    sourceAddressSignal = registerSignal("sourceAddress");
//----------------------------------------------------------//
    MyPacket *genesisPacket = new MyPacket("Genesis Block");
    genesisPacket->setByteLength(packetLengthBytes->intValue());
    genesisPacket->setKind(intuniform(0, 7));
    genesisPacket->setSrcAddr(myAddress);
    genesisPacket->setDestAddr(destAddresses[intuniform(0, destAddresses.size() - 1)]);
    genesisPacket->setPrevHash(prevHash);
    Block *genesisBlock = new Block(genesisPacket, prevHash);
    blockchain.push_back(genesisBlock);
//----------------------------------------------------------//
    GroupedNetworkData_Txt();
//----------------------------------------------------------//
}
void App::handleMessage(cMessage *msg)
{
    if (msg == generatePacket) {
//----------------------------------------------------------//
        int destAddress;
        do {
            destAddress = intuniform(1, numNodes);
        } while (destAddress == myAddress || destAddress == 54);
//----------------------------------------------------------//
        char pkname[40];
        sprintf(pkname, "pk-%d-to-%d-#%ld", myAddress, destAddress, pkCounter++);
//----------------------------------------------------------//
        EV << "generating packet " << pkname << endl;
//----------------------------------------------------------//
        MyPacket *pk = new MyPacket(pkname);
        pk->setByteLength(packetLengthBytes->intValue());
        pk->setKind(intuniform(0, 7));
        pk->setSrcAddr(myAddress);
        pk->setDestAddr(destAddress);
//----------------------------------------------------------//
        pk->setPrevHash(blockchain.back()->getHash());
        pk->setNodeRating(autorateNode(myAddress, destAddress, pk));
//----------------------------------------------------------//
        pk->setbeforeid(myAddress);
        pk->setafterid(destAddress);
//----------------------------------------------------------//
        Block *newBlock = new Block(pk, blockchain.back()->getHash());
        blockchain.push_back(newBlock);
//----------------------------------------------------------//
//Attack mechanism calling-başla
//----------------------------------------------------------//
        int victim_node = pk->getDestAddr();
        int attacker_node = myAddress;
        int attacker_node_give_value = 0;
        if (bir_grup_kotucul_nodun_bir_noda_saldirisi(attacker_node, victim_node)) {
            getParentModule()->bubble("Attack (Scenario 1)");
            attacker_node_give_value = 1;
//pk->setNodeRating(bir_grup_kotucul_nodun_bir_noda_saldirisi_autorateNode(pk));
            pk->setGroupCode("A1");
        }
        if (bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi(attacker_node)) {
            getParentModule()->bubble("Attack (Scenario 2)");
            attacker_node_give_value = 1;
            pk->setGroupCode("A2");
        }
        if (bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(attacker_node, victim_node)) {
            getParentModule()->bubble("Attack (Scenario 3)");
            attacker_node_give_value = 1;
//pk->setNodeRating(bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_autorateNode(pk));
            pk->setGroupCode("A3");
        }
//----------------------------------------------------------//
        if (attacker_node_give_value > 0) {
            send(pk, "out");
        }
        else {
            pk->setGroupCode("A0");
        }
//----------------------------------------------------------//
        scheduleAt(simTime() + sendIATime->doubleValue(), generatePacket);
//----------------------------------------------------------//
        if (hasGUI()) {
            FilesWritingPacketInformation(pk);
        }
    }
    else {
        MyPacket *pk = check_and_cast<MyPacket*>(msg);
//----------------------------------------------------------//
        EV << "received packet " << pk->getName() << " after " << pk->getHopCount() << "hops" << endl;
        emit(endToEndDelaySignal, simTime() - pk->getCreationTime());
        emit(hopCountSignal, pk->getHopCount());
        emit(sourceAddressSignal, pk->getSrcAddr());
        if (hasGUI()) {
            getParentModule()->bubble("Arrived!");
            //nodechangeColor_Blue();
            technical_information(pk);
            FilesWritingPacketInformation(pk);
        }
//----------------------------------------------------------//
        delete pk;
    }
}
//=====================================================================================/
//Attack mechanisms functions =========================================================/
//=====================================================================================/
bool App::bir_grup_kotucul_nodun_bir_noda_saldirisi(int attacker_node, int victim_node)
{
    if (attacker_node >= 0 && attacker_node <= 0 && victim_node == 0) {
        return true;
    }
    else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi(int point_giver_node)
{
    std::string dosya_tipi = bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_dosya_tipi;
    //dosya_tipi="30" ise attacker nod sayısı master kayıt sayısının verilen %30' a  kadar olan kayıtları içerir
    //dosya_tipi="40" ise attacker nod sayısı master kayıt sayısının verilen %40' a  kadar olan kayıtları içerir
    //dosya_tipi="50" ise attacker nod sayısı master kayıt sayısının verilen %50' a  kadar olan kayıtları içerir
    //dosya_tipi="60" ise attacker nod sayısı master kayıt sayısının verilen %60' a  kadar olan kayıtları içerir
    //dosya_tipi="70" ise attacker nod sayısı master kayıt sayısının verilen %70' a  kadar olan kayıtları içerir
    int point_giver_node_begin;
    int point_giver_node_end;

    if (dosya_tipi == "30") {
        point_giver_node_begin = 1;
        point_giver_node_end = 17;
    }
    else if (dosya_tipi == "40") {
        point_giver_node_begin = 1;
        point_giver_node_end = 23;
    }
    else if (dosya_tipi == "50") {
        point_giver_node_begin = 1;
        point_giver_node_end = 28;
    }
    else if (dosya_tipi == "60") {
        point_giver_node_begin = 1;
        point_giver_node_end = 34;
    }
    else if (dosya_tipi == "70") {
        point_giver_node_begin = 1;
        point_giver_node_end = 40;
    }
    else {
        point_giver_node_begin = 10;
        point_giver_node_end = 15;
    }

    if (point_giver_node >= point_giver_node_begin && point_giver_node <= point_giver_node_end) {
        return true;
    }
    else {
        return false;
    }
}
bool App::bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi(int attacker_node, int victim_node)
{
    if (attacker_node >= 0 && attacker_node <= 0 && victim_node >= 27 && victim_node <= 0) {
        std::random_device rndnd;
        std::mt19937 gen(rndnd());
        std::uniform_int_distribution<> dis(21, 30);
        bool selectedNode = dis(gen);
        return selectedNode;
    }
    else {
        return false;
    }
}
//=====================================================================================/
//Trust mechanisms functions===========================================================/
//=====================================================================================/
bool App::bir_grup_kotucul_nodun_bir_noda_saldirisi_yakalama(MyPacket *pk, int attacker_node, int victim_node)
{
    if (attacker_node >= 0 && attacker_node >= 0 && victim_node == 0) {
        FilesWritingPacketInformation(pk);
        return true;
    }
    else {
        return false;
    }
}
void App::bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_yakalama(int puan_veren_node_id, int puan_alan_node_id)
{
    std::string dosya_tipi = "-"
            + bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi_dosya_tipi;
    //dosya_tipi="30" ise attacker nod sayısı master kayıt sayısının verilen %30' a  kadar olan kayıtları içerir
    //dosya_tipi="40" ise attacker nod sayısı master kayıt sayısının verilen %40' a  kadar olan kayıtları içerir
    //dosya_tipi="50" ise attacker nod sayısı master kayıt sayısının verilen %50' a  kadar olan kayıtları içerir
    //dosya_tipi="60" ise attacker nod sayısı master kayıt sayısının verilen %60' a  kadar olan kayıtları içerir
    //dosya_tipi="70" ise attacker nod sayısı master kayıt sayısının verilen %70' a  kadar olan kayıtları içerir
    const std::string inputFilePath = "./datafiles/Ewma_Data.xml";
    const std::string outputFilePath = "./datafiles/Ewma_Data_With_Attack_A1" + dosya_tipi + ".xml";
    std::ifstream inputFile(inputFilePath);
    std::ofstream outputFile(outputFilePath);

    if (!inputFile.is_open() || !outputFile.is_open()) {
        std::cerr << "Dosya açılamadı!" << std::endl;
        return;
    }

    std::string line;
    bool isFirstLine = true; // Başlık satırını kontrol etmek için bir flag
//-------------------------------------------
    // Dosyayı satır satır oku
    while (std::getline(inputFile, line)) {
        if (isFirstLine) {
            // İlk satırsa başlık satırını yaz
            outputFile
                    << "Source_ID,CreationTime,Destination_ID,ArrivalTime,Delay,Rating,Votes,PrevHash,Ewma_Avg,AttackID\n";
            isFirstLine = false; // Flag'i false yap, bir daha yazmayacak
            continue;
        }
        //--------------------------------
        std::vector<std::string> tokens;
        size_t pos = 0;
        while ((pos = line.find("\" ")) != std::string::npos) {
            tokens.push_back(line.substr(0, pos));
            line.erase(0, pos + 2);
        }
        tokens.push_back(line); // Son kolonu ekle
        //--------------------------------
        //int sourceId = std::stoi(tokens[0]);
        //int destinationId = std::stoi(tokens[2]);
        double delay = std::stod(tokens[4]);
        int rating = std::stoi(tokens[5]);
        double ewmaavg = std::stod(tokens[8]);
        // Saldırganlık tespiti kriteri
        bool isAttack = (rating >= 10 && delay > 0.000000 && ewmaavg > 7.999999);
        // AttackID sütununu ekleyerek yeni satırı oluştur
        outputFile << tokens[0] << ", " << tokens[1] << ", " << tokens[2] << ", " << tokens[3] << ", " << tokens[4]
                << ", " << tokens[5] << ", " << tokens[6] << ", " << tokens[7] << ", " << tokens[8] << ", "
                << (isAttack ? "1" : "0") << "\n";
    }

    inputFile.close();
    outputFile.close();
    std::cout << "Saldırganlık tespiti işlemi tamamlandı. Sonuçlar " << outputFilePath << " dosyasına kaydedildi."
            << std::endl;
}
bool App::bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_yakalama(MyPacket *pk, int attacker_node, int victim_node)
{
    if (attacker_node >= 0 && attacker_node <= 0 && victim_node >= 0 && victim_node <= 0) {
        FilesWritingPacketInformation(pk);
        return true;
    }
    else {
        return false;
    }
}
//=====================================================================================/
//Autorate functions ==================================================================/
//=====================================================================================/
int App::bir_grup_kotucul_nodun_bir_noda_saldirisi_autorateNode(const MyPacket *packet)
{
    int min = 0;
    int max = 5;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
int App::bir_grup_kotucul_nodun_bayrak_yarisi_sistemi_ile_bir_grup_noda_saldirisi_autorateNode(const MyPacket *packet)
{
    int min = 0;
    int max = 5;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
//=====================================================================================/
int App::autorateNode(int attacker_node_Src, int attacker_node_Dest, MyPacket *pk)
{
    int min = 0;
    int max = 0;

    if (bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi(attacker_node_Src)
            && bir_grup_kotucul_nodun_kendi_icinde_birbirlerine_yuksek_puan_vermesi_saldirisi(attacker_node_Dest)) {
        min = 10;
        max = 10;
        nodechangeColor_Red();

    }
    else {
        min = 1;
        max = 10;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    int generatedRating = dis(gen);
    return generatedRating;
}
//=====================================================================================/
//Simulation and other functions ======================================================/
//=====================================================================================/
void App::nodechangeColor_Red()
{
    cDisplayString &displayString = getDisplayString();
    displayString.parse("i=misc/node_vs,red");
    getParentModule()->setDisplayString(displayString);
    refreshDisplay();
}
void App::nodechangeColor_Blue()
{
    cDisplayString &displayString = getDisplayString();
    displayString.parse("i=misc/node_vs,blue");
    getParentModule()->setDisplayString(displayString);
    refreshDisplay();
}
void App::technical_information(MyPacket *pk)
{
    textFigure1 = new cTextFigure("nodeIdText");
    omnetpp::cFigure::Font font("Courier", 20);
    textFigure1->setFont(font);
    EV << "Set font\n";
    textFigure1->setPosition(cFigure::Point(100, 100));
    textFigure1->setColor(cFigure::BLACK);
    textFigure1->setVisible(true);
    EV << "Configured text figure\n";
    EV << "Added text figure to canvas\n";
    EV << "Set text for text figure\n";
    cCanvas *canvas = getParentModule()->getCanvas();
    if (!canvas) {
        EV << "Error: Canvas not found." << endl;
    }
    cFigure *rootFigure = canvas->getRootFigure();
    if (!rootFigure) {
        EV << "Error: Root figure not found." << endl;
    }
    cFigure *statusFigure = rootFigure->getFigure("status");
    if (!statusFigure) {
        EV << "Error: Status figure not found." << endl;
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
    headingFigure->refreshDisplay();
    rootFigure->refreshDisplay();
}
//=====================================================================================/
//Blockchain and hash functions =======================================================/
//=====================================================================================/
std::string App::calculateHash(const MyPacket *packet)
{
    std::string packetInfo = packet->getName() + std::to_string(packet->getByteLength())
            + std::to_string(packet->getCreationTime().dbl()) + std::to_string(packet->getNodeRating());
    return calculateSHA256(packetInfo);
}
std::string App::calculateSHA256(const std::string &input) const
{
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
Block::Block(MyPacket *data, const std::string &prevHash)
{
    this->data = data;
    this->prevHash = prevHash;
    this->timestamp = time(nullptr);
    this->hash = calculateHash(App());
}
std::string Block::calculateHash(const App &app) const
{

    std::string blockInfo = prevHash + data->getName() + std::to_string(data->getByteLength())
            + std::to_string(timestamp) + std::to_string(data->getNodeRating());
    return app.calculateSHA256(blockInfo);
}
//=====================================================================================/
//Application End =====================================================================/
//=====================================================================================/
