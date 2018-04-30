#include<stdio.h>
#include"bigd.h"

BIGD n;
BIGD e;
BIGD p;
BIGD q;
BIGD dp;
BIGD dq;
BIGD cipher;
BIGD message;
BIGD test_Msg;
BIGD testC;

BIGD big1;
const int BITLENGTH = 512;

void Initialize()
{
	n = bdNew();
	bdConvFromHex(n,"6b8040f9734ab370510f561ad49bec59a647bec9fd53c0a8138be9806b8da138ecefe23afdb287933a52f3c0970d677ed730255469f5315ad0f584168b86c95fd841f198b2511810f5b666bbc041682de9fb3f610ef034b76e87b023cc3cb88a60d2d92ac974cf16d52c54ffa7f43b7ed78dd75656f1efa02d52e45d5df68733");
	
	e = bdNew();
	bdConvFromHex(e,"42d60487689ea3be5df047b88e444822f341433d58fc390303a1596252bc27d8b2137d578bfe123804197b6c61a7824f088615409565b822599c762c395bb9ac9abe36cbc0b234d47d46d3cc6eab1cb805ee73fbe8c85ece542c7d1f5d6c3a1cd9ced62b7e6f6885066b303883df92aab7aa2af5f12864d56e3558a33cea0d07");
	
	cipher = bdNew();
	bdConvFromHex(cipher,"18a3f4d3981a0572c947e1ac24803f30cc5d99a9ec2c5e09840f735392dc4581fb4fa68b4abfe259e29699eca26bec60e9baf9ca30cb6692be6525be08bda24deb2007c189d2bdd29f8a2df4c680397a47ffda08ca0a02f929403cf177e0afa468bb935c709a7cd2c3388a7da22c7626458d9b3db656355cd77fd37c578a48c6");

	test_Msg = bdNew();
	//bdConvFromHex(testM,"4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c4172746966696369616c");
	bdConvFromHex(test_Msg,"48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f48454c4c4f");

	testC = bdNew();
	bdModExp(testC, test_Msg, e, n);
	
	big1 = bdNew();
	bdSetShort(big1,1);
}
void CleanUp()
{
	bdFree(&n);
	bdFree(&e);
	bdFree(&cipher);
	bdFree(&test_Msg);
	bdFree(&testC);
	bdFree(&big1);
	bdFree(&message);
}

void Decrypt()
{
	message = bdNew();
	BIGD m1;
	m1 = bdNew();
	bdModExp(m1,cipher,dp,p);
	
	BIGD m2;
	m2 = bdNew();
	bdModExp(m2,cipher,dq,q);
	
	BIGD qinv;
	qinv = bdNew();
	bdModInv(qinv,q,p);
	
	BIGD diff;
	diff = bdNew();
	bdSubtract(diff,m1,m2);
	
	BIGD prod;
	prod = bdNew();
	bdMultiply(prod,diff,qinv);
	
	BIGD h;
	h = bdNew();
	bdModulo(h,prod,p);
	
	bdMultiply(message,h,q);
	bdAdd(message,message,m2);
	
	bdFree(&diff);
	bdFree(&prod);
	bdFree(&h);
	bdFree(&qinv);
	bdFree(&m1);
	bdFree(&m2);
}


//To check if the current dp and dq values give p and q so that pq = n

int Check()
{
	BIGD mp;
	mp = bdNew();
	
	BIGD mq;
	mq = bdNew();
	
	bdModExp(mp, testC, dp, n);
	bdModExp(mq, testC, dq, n);
	
	BIGD m_mp;
	BIGD m_mq;
	m_mp = bdNew();
	m_mq = bdNew();
	
	bdSubtract(m_mp, test_Msg, mp);
	bdSubtract(m_mq, test_Msg, mq);
	bdGcd(p, m_mp, n);
	bdGcd(q, m_mq, n);
	if(bdCompare(p,big1) == 0 && bdCompare(q,big1) == 0)
	{
		return 0;
	}
	BIGD temp;
	temp = bdNew();
	bdMultiply(temp, p, q);
	int result = bdIsEqual(temp, n) == 0?0:1; 
	bdFree(&mp);
	bdFree(&mq);
	bdFree(&m_mp);
	bdFree(&m_mq);
	bdFree(&temp);
	return result;
}
//Randomly choose dp and dq values to check for message
void BruteForceAttackRandom()
{
	int found = 0;
	do
	{
		dp = bdNew();
		dq = bdNew();
		p = bdNew();
		q = bdNew();
		bdRandomBits(dp, BITLENGTH);
		bdRandomBits(dq, BITLENGTH);
		found = Check();
		if(found == 1)
		{
			bdPrintDecimal("",p,"");
			printf("\n\n");
			bdPrintDecimal("",q,"");
			
			bdFree(&dp);
			bdFree(&dq);
			bdFree(&p);
			bdFree(&q);
			return;
		}
		bdFree(&dp);
		bdFree(&dq);
		bdFree(&p);
		bdFree(&q);
	}while(found == 0);
	
}
void PrintMessage()
{
	BIGD byte255;
	byte255 = bdNew();
	BIGD zero;
	zero = bdNew();
	BIGD lastByte;
	lastByte = bdNew();
	
	int i = 0xff;
	char str[128];
	char strmessage[300];
	int messageLength = 0;
	bdSetShort(byte255,i);
	
	while(bdCompare(message,zero) != 0)
	{	
		bdAndBits(lastByte,message,byte255);
		bdShiftRight(message,message,8);
		
		
		bdConvToDecimal(lastByte,str, sizeof(str));
		 i = atoi(str);
		char c = (char)(i);
		strmessage[messageLength] = c;
		messageLength++;
	}
	printf("\n");
	for(i = messageLength-1; i>=0; i--)
	{
		printf("%c", strmessage[i]);
	}
	bdFree(&byte255);
	bdFree(&zero);
	bdFree(&lastByte);
}
void BruteForce()
{
	BIGD upperbound_dp;
	upperbound_dp = bdNew();
	bdConvFromHex(upperbound_dp,"f4240"); //  1000000
	
	BIGD upperbound_dq;
	upperbound_dq = bdNew();
	bdConvFromHex(upperbound_dq, "f4240"); // 1000000
	
	dp = bdNew();
	dq = bdNew();
	bdSetShort(dp,0);
	bdConvFromHex(dp,"90e03");
	bdConvFromHex(dq,"91c77");
	
	
	p = bdNew();
	q = bdNew();
	while(bdCompare(dp, upperbound_dp)!=0)
	{
		bdAdd(dq, dp, big1);
		while(bdCompare(dq,upperbound_dq) != 0)
		{
			int found = 0;
			found = Check();
			if(found != 0)
			{
				printf("Values  are\ndp:\n");
				bdPrintDecimal("",dp,"");
				printf("\n");
				printf("\ndq:\n");
				bdPrintDecimal("",dq,"");
				printf("\n");
				printf("\np:\n");
				bdPrintDecimal("",p,"");
				printf("\n");
				printf("\nq:\n");
				bdPrintDecimal("",q,"");
				bdFree(&upperbound_dp);
				bdFree(&upperbound_dq);
				Decrypt();
				printf("\n");
				printf("\nThe message in plaintext:\n");
				PrintMessage();
				bdFree(&dp);
				bdFree(&dq);
				bdFree(&p);
				bdFree(&q);
				return;
			}
			bdAdd(dq,dq,big1);
		}
		bdAdd(dp,dp,big1);
	}
	bdFree(&upperbound_dp);
	bdFree(&upperbound_dq);
	bdFree(&dp);
	bdFree(&dq);
	bdFree(&p);
	bdFree(&q);	
}

int main()
{
	Initialize();
	BruteForce();
	CleanUp();
	printf("\n process complete\n");
	char c;
	scanf("%c", &c);
}
