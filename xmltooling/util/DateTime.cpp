/*
 *  Copyright 2001-2009 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * DateTime.cpp
 *
 * Manipulation of XML date/time data.
 */

/*
 * This is mostly copied from Xerces-C, but they don't seem inclined to produce a usable
 * class, so I had to incorporate my own version of it for now. I can't inherit it
 * since the fields I need are private.
 */

#include "internal.h"
#include "util/DateTime.h"

#ifndef WIN32
# include <errno.h>
#endif

#include <ctime>
#include <sstream>
#include <assert.h>
#include <xercesc/util/Janitor.hpp>

using namespace xmltooling;
using namespace xercesc;
using namespace std;

//
// constants used to process raw data (fBuffer)
//
// [-]{CCYY-MM-DD}'T'{HH:MM:SS.MS}['Z']
//                                [{+|-}hh:mm']
//

static const XMLCh DURATION_STARTER     = chLatin_P;              // 'P'
static const XMLCh DURATION_Y           = chLatin_Y;              // 'Y'
static const XMLCh DURATION_M           = chLatin_M;              // 'M'
static const XMLCh DURATION_D           = chLatin_D;              // 'D'
static const XMLCh DURATION_H           = chLatin_H;              // 'H'
static const XMLCh DURATION_S           = chLatin_S;              // 'S'

static const XMLCh DATE_SEPARATOR       = chDash;                 // '-'
static const XMLCh TIME_SEPARATOR       = chColon;                // ':'
static const XMLCh TIMEZONE_SEPARATOR   = chColon;                // ':'
static const XMLCh DATETIME_SEPARATOR   = chLatin_T;              // 'T'
static const XMLCh MILISECOND_SEPARATOR = chPeriod;               // '.'

static const XMLCh UTC_STD_CHAR         = chLatin_Z;              // 'Z'
static const XMLCh UTC_POS_CHAR         = chPlus;                 // '+'
static const XMLCh UTC_NEG_CHAR         = chDash;                 // '-'

static const XMLCh UTC_SET[]            = {UTC_STD_CHAR           //"Z+-"
                                         , UTC_POS_CHAR
                                         , UTC_NEG_CHAR
                                         , chNull};

static const int YMD_MIN_SIZE    = 10;   // CCYY-MM-DD
static const int YMONTH_MIN_SIZE = 7;    // CCYY_MM
static const int TIME_MIN_SIZE   = 8;    // hh:mm:ss
static const int TIMEZONE_SIZE   = 5;    // hh:mm
static const int DAY_SIZE        = 5;    // ---DD
//static const int MONTH_SIZE      = 6;    // --MM--
static const int MONTHDAY_SIZE   = 7;    // --MM-DD
static const int NOT_FOUND       = -1;

//define constants to be used in assigning default values for
//all date/time excluding duration
static const int YEAR_DEFAULT  = 2000;
static const int MONTH_DEFAULT = 01;
static const int DAY_DEFAULT   = 15;

// order-relation on duration is a partial order. The dates below are used to
// for comparison of 2 durations, based on the fact that
// duration x and y is x<=y iff s+x<=s+y
// see 3.2.6 duration W3C schema datatype specs
//
// the dates are in format: {CCYY,MM,DD, H, S, M, MS, timezone}
const int DateTime::DATETIMES[][TOTAL_SIZE] =
{
    {1696, 9, 1, 0, 0, 0, 0, UTC_STD},
	{1697, 2, 1, 0, 0, 0, 0, UTC_STD},
	{1903, 3, 1, 0, 0, 0, 0, UTC_STD},
	{1903, 7, 1, 0, 0, 0, 0, UTC_STD}
};

// ---------------------------------------------------------------------------
//  local methods
// ---------------------------------------------------------------------------
static inline int fQuotient(int a, int b)
{
    div_t div_result = div(a, b);
    return div_result.quot;
}

static inline int fQuotient(int temp, int low, int high)
{
    return fQuotient(temp - low, high - low);
}

static inline int mod(int a, int b, int quotient)
{
	return (a - quotient*b) ;
}

static inline int modulo (int temp, int low, int high)
{
    //modulo(a - low, high - low) + low
    int a = temp - low;
    int b = high - low;
    return (mod (a, b, fQuotient(a, b)) + low) ;
}

static inline bool isLeapYear(int year)
{
    return((year%4 == 0) && ((year%100 != 0) || (year%400 == 0)));
}

static int maxDayInMonthFor(int year, int month)
{

    if ( month == 4 || month == 6 || month == 9 || month == 11 )
    {
        return 30;
    }
    else if ( month==2 )
    {
        if ( isLeapYear(year) )
            return 29;
        else
            return 28;
    }
    else
    {
        return 31;
    }

}

// ---------------------------------------------------------------------------
//  static methods : for duration
// ---------------------------------------------------------------------------
/**
 * Compares 2 given durations. (refer to W3C Schema Datatypes "3.2.6 duration")
 *
 * 3.2.6.2 Order relation on duration
 *
 *     In general, the order-relation on duration is a partial order since there is no
 *  determinate relationship between certain durations such as one month (P1M) and 30 days (P30D).
 *  The order-relation of two duration values x and y is x < y iff s+x < s+y for each qualified
 *  dateTime s in the list below.
 *
 *     These values for s cause the greatest deviations in the addition of dateTimes and durations
 *
 **/
int DateTime::compare(const DateTime* const pDate1
                       , const DateTime* const pDate2
                       , bool  strict)
{
    //REVISIT: this is unoptimazed vs of comparing 2 durations
    //         Algorithm is described in 3.2.6.2 W3C Schema Datatype specs
    //

    int resultA, resultB = XMLDateTime::INDETERMINATE;

    //try and see if the objects are equal
    if ( (resultA = compareOrder(pDate1, pDate2)) == XMLDateTime::EQUAL)
        return XMLDateTime::EQUAL;

    //long comparison algorithm is required
    DateTime tempA, *pTempA = &tempA;
    DateTime tempB, *pTempB = &tempB;

    addDuration(pTempA, pDate1, 0);
    addDuration(pTempB, pDate2, 0);
    resultA = compareOrder(pTempA, pTempB);
    if ( resultA == XMLDateTime::INDETERMINATE )
        return XMLDateTime::INDETERMINATE;

    addDuration(pTempA, pDate1, 1);
    addDuration(pTempB, pDate2, 1);
    resultB = compareOrder(pTempA, pTempB);
    resultA = compareResult(resultA, resultB, strict);
    if ( resultA == XMLDateTime::INDETERMINATE )
        return XMLDateTime::INDETERMINATE;

    addDuration(pTempA, pDate1, 2);
    addDuration(pTempB, pDate2, 2);
    resultB = compareOrder(pTempA, pTempB);
    resultA = compareResult(resultA, resultB, strict);
    if ( resultA == XMLDateTime::INDETERMINATE )
        return XMLDateTime::INDETERMINATE;

    addDuration(pTempA, pDate1, 3);
    addDuration(pTempB, pDate2, 3);
    resultB = compareOrder(pTempA, pTempB);
    resultA = compareResult(resultA, resultB, strict);

    return resultA;

}

//
// Form a new DateTime with duration and baseDate array
// Note: C++        Java
//       fNewDate   duration
//       fDuration  date
//

void DateTime::addDuration(DateTime*             fNewDate
                            , const DateTime* const fDuration
                            , int index)

{

    //REVISIT: some code could be shared between normalize() and this method,
    //         however is it worth moving it? The structures are different...
    //

    fNewDate->reset();
    //add months (may be modified additionaly below)
    int temp = DATETIMES[index][Month] + fDuration->fValue[Month];
    fNewDate->fValue[Month] = modulo(temp, 1, 13);
    int carry = fQuotient(temp, 1, 13);

    //add years (may be modified additionaly below)
    fNewDate->fValue[CentYear] =
        DATETIMES[index][CentYear] + fDuration->fValue[CentYear] + carry;

    //add seconds
    temp = DATETIMES[index][Second] + fDuration->fValue[Second];
    carry = fQuotient (temp, 60);
    fNewDate->fValue[Second] =  mod(temp, 60, carry);

    //add minutes
    temp = DATETIMES[index][Minute] + fDuration->fValue[Minute] + carry;
    carry = fQuotient(temp, 60);
    fNewDate->fValue[Minute] = mod(temp, 60, carry);

    //add hours
    temp = DATETIMES[index][Hour] + fDuration->fValue[Hour] + carry;
    carry = fQuotient(temp, 24);
    fNewDate->fValue[Hour] = mod(temp, 24, carry);

    fNewDate->fValue[Day] =
        DATETIMES[index][Day] + fDuration->fValue[Day] + carry;

    while ( true )
    {
        temp = maxDayInMonthFor(fNewDate->fValue[CentYear], fNewDate->fValue[Month]);
        if ( fNewDate->fValue[Day] < 1 )
        { //original fNewDate was negative
            fNewDate->fValue[Day] +=
                maxDayInMonthFor(fNewDate->fValue[CentYear], fNewDate->fValue[Month]-1);
            carry = -1;
        }
        else if ( fNewDate->fValue[Day] > temp )
        {
            fNewDate->fValue[Day] -= temp;
            carry = 1;
        }
        else
        {
            break;
        }

        temp = fNewDate->fValue[Month] + carry;
        fNewDate->fValue[Month] = modulo(temp, 1, 13);
        fNewDate->fValue[CentYear] += fQuotient(temp, 1, 13);
    }

    //fNewDate->fValue[utc] = UTC_STD_CHAR;
    fNewDate->fValue[utc] = UTC_STD;
}

int DateTime::compareResult(int resultA
                             , int resultB
                             , bool strict)
{

    if ( resultB == XMLDateTime::INDETERMINATE )
    {
        return XMLDateTime::INDETERMINATE;
    }
    else if ( (resultA != resultB) &&
              strict                )
    {
        return XMLDateTime::INDETERMINATE;
    }
    else if ( (resultA != resultB) &&
              !strict               )
    {
        if ( (resultA != XMLDateTime::EQUAL) &&
             (resultB != XMLDateTime::EQUAL)  )
        {
            return XMLDateTime::INDETERMINATE;
        }
        else
        {
            return (resultA != XMLDateTime::EQUAL)? resultA : resultB;
        }
    }

    return resultA;

}

// ---------------------------------------------------------------------------
//  static methods : for others
// ---------------------------------------------------------------------------
int DateTime::compare(const DateTime* const pDate1
                       , const DateTime* const pDate2)
{

    if (pDate1->fValue[utc] == pDate2->fValue[utc])
    {
        return DateTime::compareOrder(pDate1, pDate2);
    }

    int c1, c2;

    if ( pDate1->isNormalized())
    {
        c1 = compareResult(pDate1, pDate2, false, UTC_POS);
        c2 = compareResult(pDate1, pDate2, false, UTC_NEG);
        return getRetVal(c1, c2);
    }
    else if ( pDate2->isNormalized())
    {
        c1 = compareResult(pDate1, pDate2, true, UTC_POS);
        c2 = compareResult(pDate1, pDate2, true, UTC_NEG);
        return getRetVal(c1, c2);
    }

    return XMLDateTime::INDETERMINATE;
}

int DateTime::compareResult(const DateTime* const pDate1
                             , const DateTime* const pDate2
                             , bool  set2Left
                             , int   utc_type)
{
    DateTime tmpDate = (set2Left ? *pDate1 : *pDate2);

    tmpDate.fTimeZone[hh] = 14;
    tmpDate.fTimeZone[mm] = 0;
    tmpDate.fValue[utc] = utc_type;
    tmpDate.normalize();

    return (set2Left? DateTime::compareOrder(&tmpDate, pDate2) :
                      DateTime::compareOrder(pDate1, &tmpDate));
}

int DateTime::compareOrder(const DateTime* const lValue
                            , const DateTime* const rValue)
                            //, MemoryManager* const memMgr)
{
    //
    // If any of the them is not normalized() yet,
    // we need to do something here.
    //
    DateTime lTemp = *lValue;
    DateTime rTemp = *rValue;

    lTemp.normalize();
    rTemp.normalize();

    for ( int i = 0 ; i < TOTAL_SIZE; i++ )
    {
        if ( lTemp.fValue[i] < rTemp.fValue[i] )
        {
            return XMLDateTime::LESS_THAN;
        }
        else if ( lTemp.fValue[i] > rTemp.fValue[i] )
        {
            return XMLDateTime::GREATER_THAN;
        }
    }

    if ( lTemp.fHasTime)
    {
        if ( lTemp.fMiliSecond < rTemp.fMiliSecond )
        {
            return XMLDateTime::LESS_THAN;
        }
        else if ( lTemp.fMiliSecond > rTemp.fMiliSecond )
        {
            return XMLDateTime::GREATER_THAN;
        }
    }

    return XMLDateTime::EQUAL;
}

// ---------------------------------------------------------------------------
//  ctor and dtor
// ---------------------------------------------------------------------------
DateTime::~DateTime()
{
    delete[] fBuffer;
}

DateTime::DateTime()
: fStart(0)
, fEnd(0)
, fBufferMaxLen(0)
, fBuffer(0)
, fMiliSecond(0)
, fHasTime(false)
{
    reset();
}

DateTime::DateTime(const XMLCh* const aString)
: fStart(0)
, fEnd(0)
, fBufferMaxLen(0)
, fBuffer(0)
, fMiliSecond(0)
, fHasTime(false)
{
    setBuffer(aString);
}

DateTime::DateTime(time_t epoch, bool duration)
: fStart(0)
, fEnd(0)
, fBufferMaxLen(0)
, fBuffer(0)
, fMiliSecond(0)
, fHasTime(false)
{
    if (duration) {
        ostringstream s;
        if (epoch < 0) {
            s << "-";
            epoch = -epoch;
        }
        time_t days = epoch / 86400;
        epoch %= 86400;
        time_t hours = epoch / 3600;
        epoch %= 3600;
        time_t minutes = epoch / 60;
        epoch %= 60;
        s << "P" << days << "DT" << hours << "H" << minutes << "M" << epoch << "S";
        auto_ptr_XMLCh timeptr(s.str().c_str());
        setBuffer(timeptr.get());
    }
    else {
#ifndef HAVE_GMTIME_R
        struct tm* ptime=gmtime(&epoch);
#else
        struct tm res;
        struct tm* ptime=gmtime_r(&epoch,&res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
        auto_ptr_XMLCh timeptr(timebuf);
        setBuffer(timeptr.get());
    }
}

// -----------------------------------------------------------------------
// Copy ctor and Assignment operators
// -----------------------------------------------------------------------

DateTime::DateTime(const DateTime &toCopy)
: fBufferMaxLen(0)
, fBuffer(0)
{
    copy(toCopy);
}

DateTime& DateTime::operator=(const DateTime& rhs)
{
    if (this == &rhs)
        return *this;

    copy(rhs);
    return *this;
}

// -----------------------------------------------------------------------
// Implementation of Abstract Interface
// -----------------------------------------------------------------------

//
// We may simply return the handle to fBuffer
//
const XMLCh*  DateTime::getRawData() const
{
    //assertBuffer();
    return fBuffer;
}


const XMLCh*  DateTime::getFormattedString() const
{
    return getRawData();
}

int DateTime::getSign() const
{
    return fValue[utc];
}

time_t DateTime::getEpoch(bool duration) const
{
    if (duration) {
        time_t epoch = getSecond() + (60 * getMinute()) + (3600 * getHour()) + (86400 * getDay());
        if (getMonth())
            epoch += (((365 * 4) + 1)/48 * 86400);
        if (getYear())
            epoch += 365.25 * 86400;
        return getSign()!=UTC_NEG ? epoch : -epoch;
    }
    else {
        struct tm t;
        t.tm_sec=getSecond();
        t.tm_min=getMinute();
        t.tm_hour=getHour();
        t.tm_mday=getDay();
        t.tm_mon=getMonth()-1;
        t.tm_year=getYear()-1900;
        t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
        return timegm(&t);
#else
        // Windows, and hopefully most others...?
        return mktime(&t) - timezone;
#endif
    }
}

// ---------------------------------------------------------------------------
//  Parsers
// ---------------------------------------------------------------------------

//
// [-]{CCYY-MM-DD}'T'{HH:MM:SS.MS}[TimeZone]
//
void DateTime::parseDateTime()
{
    initParser();
    getDate();

    //fStart is supposed to point to 'T'
    if (fBuffer[fStart++] != DATETIME_SEPARATOR)
        throw XMLParserException("Invalid separator between date and time.");

    getTime();
    validateDateTime();
    normalize();
    fHasTime = true;
}

//
// [-]{CCYY-MM-DD}[TimeZone]
//
void DateTime::parseDate()
{
    initParser();
    getDate();
    parseTimeZone();
    validateDateTime();
    normalize();
}

void DateTime::parseTime()
{
    initParser();

    // time initialize to default values
    fValue[CentYear]= YEAR_DEFAULT;
    fValue[Month]   = MONTH_DEFAULT;
    fValue[Day]     = DAY_DEFAULT;

    getTime();

    validateDateTime();
    normalize();
    fHasTime = true;
}

//
// {---DD}[TimeZone]
//  01234
//
void DateTime::parseDay()
{
    initParser();

    if (fBuffer[0] != DATE_SEPARATOR ||
        fBuffer[1] != DATE_SEPARATOR ||
        fBuffer[2] != DATE_SEPARATOR  )
    {
        throw XMLParserException("Invalid character in date.");
    }

    //initialize values
    fValue[CentYear] = YEAR_DEFAULT;
    fValue[Month]    = MONTH_DEFAULT;
    fValue[Day]      = parseInt(fStart+3, fStart+5);

    if ( DAY_SIZE < fEnd )
    {
        int sign = findUTCSign(DAY_SIZE);
        if ( sign < 0 )
        {
            throw XMLParserException("Invalid character in date.");
        }
        else
        {
            getTimeZone(sign);
        }
    }

    validateDateTime();
    normalize();
}

//
// {--MM--}[TimeZone]
// {--MM}[TimeZone]
//  012345
//
void DateTime::parseMonth()
{
    initParser();

    if (fBuffer[0] != DATE_SEPARATOR ||
        fBuffer[1] != DATE_SEPARATOR  )
    {
        throw XMLParserException("Invalid character in date.");
    }

    //set constants
    fValue[CentYear] = YEAR_DEFAULT;
    fValue[Day]      = DAY_DEFAULT;
    fValue[Month]    = parseInt(2, 4);

    // REVISIT: allow both --MM and --MM-- now.
    // need to remove the following lines to disallow --MM--
    // when the errata is officially in the rec.
    fStart = 4;
    if ( fEnd >= fStart+2 && fBuffer[fStart] == DATE_SEPARATOR && fBuffer[fStart+1] == DATE_SEPARATOR )
    {
        fStart += 2;
    }

    //
    // parse TimeZone if any
    //
    if ( fStart < fEnd )
    {
        int sign = findUTCSign(fStart);
        if ( sign < 0 )
        {
            throw XMLParserException("Invalid character in date.");
        }
        else
        {
            getTimeZone(sign);
        }
    }

    validateDateTime();
    normalize();
}

//
//[-]{CCYY}[TimeZone]
// 0  1234
//
void DateTime::parseYear()
{
    initParser();

    // skip the first '-' and search for timezone
    //
    int sign = findUTCSign((fBuffer[0] == chDash) ? 1 : 0);

    if (sign == NOT_FOUND)
    {
        fValue[CentYear] = parseIntYear(fEnd);
    }
    else
    {
        fValue[CentYear] = parseIntYear(sign);
        getTimeZone(sign);
    }

    //initialize values
    fValue[Month] = MONTH_DEFAULT;
    fValue[Day]   = DAY_DEFAULT;   //java is 1

    validateDateTime();
    normalize();
}

//
//{--MM-DD}[TimeZone]
// 0123456
//
void DateTime::parseMonthDay()
{
    initParser();

    if (fBuffer[0] != DATE_SEPARATOR ||
        fBuffer[1] != DATE_SEPARATOR ||
        fBuffer[4] != DATE_SEPARATOR )
    {
        throw XMLParserException("Invalid character in date.");
    }


    //initialize
    fValue[CentYear] = YEAR_DEFAULT;
    fValue[Month]    = parseInt(2, 4);
    fValue[Day]      = parseInt(5, 7);

    if ( MONTHDAY_SIZE < fEnd )
    {
        int sign = findUTCSign(MONTHDAY_SIZE);
        if ( sign<0 )
        {
            throw XMLParserException("Invalid character in date.");
        }
        else
        {
            getTimeZone(sign);
        }
    }

    validateDateTime();
    normalize();
}

void DateTime::parseYearMonth()
{
    initParser();

    // get date
    getYearMonth();
    fValue[Day] = DAY_DEFAULT;
    parseTimeZone();

    validateDateTime();
    normalize();
}

//
//PnYn MnDTnH nMnS: -P1Y2M3DT10H30M
//
// [-]{'P'{[n'Y'][n'M'][n'D']['T'][n'H'][n'M'][n'S']}}
//
//  Note: the n above shall be >= 0
//        if no time element found, 'T' shall be absent
//
void DateTime::parseDuration()
{
    initParser();

    // must start with '-' or 'P'
    //
    XMLCh c = fBuffer[fStart++];
    if ( (c != DURATION_STARTER) &&
         (c != chDash)            )
    {
        throw XMLParserException("Invalid character in time.");
    }

    // 'P' must ALWAYS be present in either case
    if ( (c == chDash) &&
         (fBuffer[fStart++]!= DURATION_STARTER ))
    {
        throw XMLParserException("Invalid character in time.");
    }

    // java code
    //date[utc]=(c=='-')?'-':0;
    //fValue[utc] = UTC_STD;
    fValue[utc] = (fBuffer[0] == chDash? UTC_NEG : UTC_STD);

    int negate = ( fBuffer[0] == chDash ? -1 : 1);

    //
    // No negative value is allowed after 'P'
    //
    // eg P-1234, invalid
    //
    if (indexOf(fStart, fEnd, chDash) != NOT_FOUND)
    {
        throw XMLParserException("Invalid character in time.");
    }

    //at least one number and designator must be seen after P
    bool designator = false;

    int endDate = indexOf(fStart, fEnd, DATETIME_SEPARATOR);
    if ( endDate == NOT_FOUND )
    {
        endDate = fEnd;  // 'T' absent
    }

    //find 'Y'
    int end = indexOf(fStart, endDate, DURATION_Y);
    if ( end != NOT_FOUND )
    {
        //scan year
        fValue[CentYear] = negate * parseInt(fStart, end);
        fStart = end+1;
        designator = true;
    }

    end = indexOf(fStart, endDate, DURATION_M);
    if ( end != NOT_FOUND )
    {
        //scan month
        fValue[Month] = negate * parseInt(fStart, end);
        fStart = end+1;
        designator = true;
    }

    end = indexOf(fStart, endDate, DURATION_D);
    if ( end != NOT_FOUND )
    {
        //scan day
        fValue[Day] = negate * parseInt(fStart,end);
        fStart = end+1;
        designator = true;
    }

    if ( (fEnd == endDate) &&   // 'T' absent
         (fStart != fEnd)   )   // something after Day
    {
        throw XMLParserException("Invalid character in time.");
    }

    if ( fEnd != endDate ) // 'T' present
    {
        //scan hours, minutes, seconds
        //

        // skip 'T' first
        end = indexOf(++fStart, fEnd, DURATION_H);
        if ( end != NOT_FOUND )
        {
            //scan hours
            fValue[Hour] = negate * parseInt(fStart, end);
            fStart = end+1;
            designator = true;
        }

        end = indexOf(fStart, fEnd, DURATION_M);
        if ( end != NOT_FOUND )
        {
            //scan min
            fValue[Minute] = negate * parseInt(fStart, end);
            fStart = end+1;
            designator = true;
        }

        end = indexOf(fStart, fEnd, DURATION_S);
        if ( end != NOT_FOUND )
        {
            //scan seconds
            int mlsec = indexOf (fStart, end, MILISECOND_SEPARATOR);

            /***
             * Schema Errata: E2-23
             * at least one digit must follow the decimal point if it appears.
             * That is, the value of the seconds component must conform
             * to the following pattern: [0-9]+(.[0-9]+)?
             */
            if ( mlsec != NOT_FOUND )
            {
                /***
                 * make usure there is something after the '.' and before the end.
                 */
                if ( mlsec+1 == end )
                {
                    throw XMLParserException("Invalid character in time.");
                }

                fValue[Second]     = negate * parseInt(fStart, mlsec);
                fMiliSecond        = negate * parseMiliSecond(mlsec+1, end);
            }
            else
            {
                fValue[Second] = negate * parseInt(fStart,end);
            }

            fStart = end+1;
            designator = true;
        }

        // no additional data should appear after last item
        // P1Y1M1DT is illigal value as well
        if ( (fStart != fEnd) ||
              fBuffer[--fStart] == DATETIME_SEPARATOR )
        {
            throw XMLParserException("Invalid character in time.");
        }
    }

    if ( !designator )
    {
        throw XMLParserException("Invalid character in time.");
    }

}

// ---------------------------------------------------------------------------
//  Scanners
// ---------------------------------------------------------------------------

//
// [-]{CCYY-MM-DD}
//
// Note: CCYY could be more than 4 digits
//       Assuming fStart point to the beginning of the Date Section
//       fStart updated to point to the position right AFTER the second 'D'
//       Since the lenght of CCYY might be variable, we can't check format upfront
//
void DateTime::getDate()
{

    // Ensure enough chars in buffer
    if ( (fStart+YMD_MIN_SIZE) > fEnd)
        throw XMLParserException("Date/time string not complete.");

    getYearMonth();    // Scan YearMonth and
                       // fStart point to the next '-'

    if (fBuffer[fStart++] != DATE_SEPARATOR)
    {
        throw XMLParserException("CCYY-MM must be followed by '-' sign.");
    }

    fValue[Day] = parseInt(fStart, fStart+2);
    fStart += 2 ;  //fStart points right after the Day

    return;
}

//
// hh:mm:ss[.msssss]['Z']
// hh:mm:ss[.msssss][['+'|'-']hh:mm]
// 012345678
//
// Note: Assuming fStart point to the beginning of the Time Section
//       fStart updated to point to the position right AFTER the second 's'
//                                                  or ms if any
//
void DateTime::getTime()
{

    // Ensure enough chars in buffer
    if ( (fStart+TIME_MIN_SIZE) > fEnd)
        throw XMLParserException("Incomplete Time Format.");

    // check (fixed) format first
    if ((fBuffer[fStart + 2] != TIME_SEPARATOR) ||
        (fBuffer[fStart + 5] != TIME_SEPARATOR)  )
    {
        throw XMLParserException("Error in parsing time.");
    }

    //
    // get hours, minute and second
    //
    fValue[Hour]   = parseInt(fStart + 0, fStart + 2);
    fValue[Minute] = parseInt(fStart + 3, fStart + 5);
    fValue[Second] = parseInt(fStart + 6, fStart + 8);
    fStart += 8;

    // to see if any ms and/or utc part after that
    if (fStart >= fEnd)
        return;

    //find UTC sign if any
    int sign = findUTCSign(fStart);

    //parse miliseconds
    int milisec = (fBuffer[fStart] == MILISECOND_SEPARATOR)? fStart : NOT_FOUND;
    if ( milisec != NOT_FOUND )
    {
        fStart++;   // skip the '.'
        // make sure we have some thing between the '.' and fEnd
        if (fStart >= fEnd)
        {
            throw XMLParserException("ms should be present once '.' is present.");
        }

        if ( sign == NOT_FOUND )
        {
            fMiliSecond = parseMiliSecond(fStart, fEnd);  //get ms between '.' and fEnd
            fStart = fEnd;
        }
        else
        {
            fMiliSecond = parseMiliSecond(fStart, sign);  //get ms between UTC sign and fEnd
        }
	}
    else if(sign == 0 || sign != fStart)
    {
        throw XMLParserException("Seconds has more than 2 digits.");
    }

    //parse UTC time zone (hh:mm)
    if ( sign > 0 ) {
        getTimeZone(sign);
    }

}

//
// [-]{CCYY-MM}
//
// Note: CCYY could be more than 4 digits
//       fStart updated to point AFTER the second 'M' (probably meet the fEnd)
//
void DateTime::getYearMonth()
{

    // Ensure enough chars in buffer
    if ( (fStart+YMONTH_MIN_SIZE) > fEnd)
        throw XMLParserException("Incomplete YearMonth Format.");

    // skip the first leading '-'
    int start = ( fBuffer[0] == chDash ) ? fStart + 1 : fStart;

    //
    // search for year separator '-'
    //
    int yearSeparator = indexOf(start, fEnd, DATE_SEPARATOR);
    if ( yearSeparator == NOT_FOUND)
        throw XMLParserException("Year separator is missing or misplaced.");

    fValue[CentYear] = parseIntYear(yearSeparator);
    fStart = yearSeparator + 1;  //skip the '-' and point to the first M

    //
    //gonna check we have enough byte for month
    //
    if ((fStart + 2) > fEnd )
        throw XMLParserException("No month in buffer.");

    fValue[Month] = parseInt(fStart, yearSeparator + 3);
    fStart += 2;  //fStart points right after the MONTH

    return;
}

void DateTime::parseTimeZone()
{
    if ( fStart < fEnd )
    {
        int sign = findUTCSign(fStart);
        if ( sign < 0 )
        {
            throw XMLParserException("Error in month parsing.");
        }
        else
        {
            getTimeZone(sign);
        }
    }

    return;
}

//
// 'Z'
// ['+'|'-']hh:mm
//
// Note: Assuming fStart points to the beginning of TimeZone section
//       fStart updated to meet fEnd
//
void DateTime::getTimeZone(const int sign)
{

    if ( fBuffer[sign] == UTC_STD_CHAR )
    {
        if ((sign + 1) != fEnd )
        {
            throw XMLParserException("Error in parsing time zone.");
        }

        return;
    }

    //
    // otherwise, it has to be this format
    // '[+|-]'hh:mm
    //    1   23456 7
    //   sign      fEnd
    //
    if ( ( ( sign + TIMEZONE_SIZE + 1) != fEnd )      ||
         ( fBuffer[sign + 3] != TIMEZONE_SEPARATOR ) )
    {
        throw XMLParserException("Error in parsing time zone.");
    }

    fTimeZone[hh] = parseInt(sign+1, sign+3);
    fTimeZone[mm] = parseInt(sign+4, fEnd);

    return;
}

// ---------------------------------------------------------------------------
//  Validator and normalizer
// ---------------------------------------------------------------------------

/**
 * If timezone present - normalize dateTime  [E Adding durations to dateTimes]
 *
 * @param date   CCYY-MM-DDThh:mm:ss+03
 * @return CCYY-MM-DDThh:mm:ssZ
 */
void DateTime::normalize()
{

    if ((fValue[utc] == UTC_UNKNOWN) ||
        (fValue[utc] == UTC_STD)      )
        return;

    int negate = (fValue[utc] == UTC_POS)? -1: 1;

    // add mins
    int temp = fValue[Minute] + negate * fTimeZone[mm];
    int carry = fQuotient(temp, 60);
    fValue[Minute] = mod(temp, 60, carry);

    //add hours
    temp = fValue[Hour] + negate * fTimeZone[hh] + carry;
    carry = fQuotient(temp, 24);
    fValue[Hour] = mod(temp, 24, carry);

    fValue[Day] += carry;

    while (1)
    {
        temp = maxDayInMonthFor(fValue[CentYear], fValue[Month]);
        if (fValue[Day] < 1)
        {
            fValue[Day] += maxDayInMonthFor(fValue[CentYear], fValue[Month] - 1);
            carry = -1;
        }
        else if ( fValue[Day] > temp )
        {
            fValue[Day] -= temp;
            carry = 1;
        }
        else
        {
            break;
        }

        temp = fValue[Month] + carry;
        fValue[Month] = modulo(temp, 1, 13);
        fValue[CentYear] += fQuotient(temp, 1, 13);
    }

    // set to normalized
    fValue[utc] = UTC_STD;

    return;
}

void DateTime::validateDateTime() const
{

    //REVISIT: should we throw an exception for not valid dates
    //          or reporting an error message should be sufficient?
    if ( fValue[CentYear] == 0 )
    {
        throw XMLParserException("The year \"0000\" is an illegal year value");
    }

    if ( fValue[Month] < 1  ||
         fValue[Month] > 12  )
    {
        throw XMLParserException("The month must have values 1 to 12");
    }

    //validate days
    if ( fValue[Day] > maxDayInMonthFor( fValue[CentYear], fValue[Month]) ||
         fValue[Day] == 0 )
    {
        throw XMLParserException("The day must have values 1 to 31");
    }

    //validate hours
    if ((fValue[Hour] < 0)  ||
        (fValue[Hour] > 24) ||
        ((fValue[Hour] == 24) && ((fValue[Minute] !=0) ||
                                  (fValue[Second] !=0) ||
                                  (fMiliSecond    !=0))))
    {
        throw XMLParserException("Hour must have values 0-23");
    }

    //validate minutes
    if ( fValue[Minute] < 0 ||
         fValue[Minute] > 59 )
    {
        throw XMLParserException("Minute must have values 0-59");
    }

    //validate seconds
    if ( fValue[Second] < 0 ||
         fValue[Second] > 60 )
    {
        throw XMLParserException("Second must have values 0-60");
    }

    //validate time-zone hours
    if ( (abs(fTimeZone[hh]) > 14) ||
         ((abs(fTimeZone[hh]) == 14) && (fTimeZone[mm] != 0)) )
    {
        throw XMLParserException("Time zone should have range -14..+14");
    }

    //validate time-zone minutes
    if ( abs(fTimeZone[mm]) > 59 )
    {
        throw XMLParserException("Minute must have values 0-59");
    }

    return;
}

// -----------------------------------------------------------------------
// locator and converter
// -----------------------------------------------------------------------
int DateTime::indexOf(const int start, const int end, const XMLCh ch) const
{
    for ( int i = start; i < end; i++ )
        if ( fBuffer[i] == ch )
            return i;

    return NOT_FOUND;
}

int DateTime::findUTCSign (const int start)
{
    int  pos;
    for ( int index = start; index < fEnd; index++ )
    {
        pos = XMLString::indexOf(UTC_SET, fBuffer[index]);
        if ( pos != NOT_FOUND)
        {
            fValue[utc] = pos+1;   // refer to utcType, there is 1 diff
            return index;
        }
    }

    return NOT_FOUND;
}

//
// Note:
//    start: starting point in fBuffer
//    end:   ending point in fBuffer (exclusive)
//    fStart NOT updated
//
int DateTime::parseInt(const int start, const int end) const
{
    unsigned int retVal = 0;
    for (int i=start; i < end; i++) {

        if (fBuffer[i] < chDigit_0 || fBuffer[i] > chDigit_9)
            throw XMLParserException("Invalid non-numeric characters.");

        retVal = (retVal * 10) + (unsigned int) (fBuffer[i] - chDigit_0);
    }

    return (int) retVal;
}

//
// Note:
//    start: pointing to the first digit after the '.'
//    end:   pointing to one position after the last digit
//    fStart NOT updated
//
double DateTime::parseMiliSecond(const int start, const int end) const
{

    unsigned int  miliSecLen = (end-1) - (start-1) + 1; //to include the '.'
    XMLCh* miliSecData = new XMLCh[miliSecLen + 1];
    ArrayJanitor<XMLCh> janMili(miliSecData);
    XMLString::copyNString(miliSecData, &(fBuffer[start-1]), miliSecLen);
    *(miliSecData + miliSecLen) = chNull;

    char *nptr = XMLString::transcode(miliSecData);
    ArrayJanitor<char> jan(nptr);
    size_t   strLen = strlen(nptr);
    char *endptr = 0;
    errno = 0;

    //printf("milisec=<%s>\n", nptr);

    double retVal = strtod(nptr, &endptr);

    // check if all chars are valid char
    if ( (endptr - nptr) != strLen)
        throw XMLParserException("Invalid non-numeric characters.");

    // we don't check underflow occurs since
    // nothing we can do about it.
    return retVal;
}

//
// [-]CCYY
//
// Note: start from fStart
//       end (exclusive)
//       fStart NOT updated
//
int DateTime::parseIntYear(const int end) const
{
    // skip the first leading '-'
    int start = ( fBuffer[0] == chDash ) ? fStart + 1 : fStart;

    int length = end - start;
    if (length < 4)
    {
        throw XMLParserException("Year must have 'CCYY' format");
    }
    else if (length > 4 &&
             fBuffer[start] == chDigit_0)
    {
        throw XMLParserException("Leading zeros are required if the year value would otherwise have fewer than four digits; otherwise they are forbidden.");
    }

    bool negative = (fBuffer[0] == chDash);
    int  yearVal = parseInt((negative ? 1 : 0), end);
    return ( negative ? (-1) * yearVal : yearVal );
}

/***
 * E2-41
 *
 *  3.2.7.2 Canonical representation
 *
 *  Except for trailing fractional zero digits in the seconds representation,
 *  '24:00:00' time representations, and timezone (for timezoned values),
 *  the mapping from literals to values is one-to-one. Where there is more
 *  than one possible representation, the canonical representation is as follows:
 *  redundant trailing zero digits in fractional-second literals are prohibited.
 *  An hour representation of '24' is prohibited. Timezoned values are canonically
 *  represented by appending 'Z' to the nontimezoned representation. (All
 *  timezoned dateTime values are UTC.)
 *
 *  .'24:00:00' -> '00:00:00'
 *  .milisecond: trailing zeros removed
 *  .'Z'
 *
 ***/
XMLCh* DateTime::getDateTimeCanonicalRepresentation() const
{
    XMLCh *miliStartPtr, *miliEndPtr;
    searchMiliSeconds(miliStartPtr, miliEndPtr);
    size_t miliSecondsLen = miliEndPtr - miliStartPtr;

    XMLCh* retBuf = new XMLCh[21 + miliSecondsLen + 2];
    XMLCh* retPtr = retBuf;

    // (-?) cc+yy-mm-dd'T'hh:mm:ss'Z'    ('.'s+)?
    //      2+  8       1      8   1
    //
    int additionalLen = fillYearString(retPtr, CentYear);
    if(additionalLen != 0)
    {
        // very bad luck; have to resize the buffer...
        XMLCh *tmpBuf = new XMLCh[additionalLen+21+miliSecondsLen +2];
        XMLString::moveChars(tmpBuf, retBuf, 4+additionalLen);
        retPtr = tmpBuf+(retPtr-retBuf);
        delete[] retBuf;
        retBuf = tmpBuf;
    }
    *retPtr++ = DATE_SEPARATOR;
    fillString(retPtr, Month, 2);
    *retPtr++ = DATE_SEPARATOR;
    fillString(retPtr, Day, 2);
    *retPtr++ = DATETIME_SEPARATOR;

    fillString(retPtr, Hour, 2);
    if (fValue[Hour] == 24)
    {
        *(retPtr - 2) = chDigit_0;
        *(retPtr - 1) = chDigit_0;
    }
    *retPtr++ = TIME_SEPARATOR;
    fillString(retPtr, Minute, 2);
    *retPtr++ = TIME_SEPARATOR;
    fillString(retPtr, Second, 2);

    if (miliSecondsLen)
    {
        *retPtr++ = chPeriod;
        XMLString::copyNString(retPtr, miliStartPtr, miliSecondsLen);
        retPtr += miliSecondsLen;
    }

    *retPtr++ = UTC_STD_CHAR;
    *retPtr = chNull;

    return retBuf;
}

/***
 * 3.2.8 time
 *
 *  . either the time zone must be omitted or,
 *    if present, the time zone must be Coordinated Universal Time (UTC) indicated by a "Z".
 *
 *  . Additionally, the canonical representation for midnight is 00:00:00.
 *
***/
XMLCh* DateTime::getTimeCanonicalRepresentation() const
{
    XMLCh *miliStartPtr, *miliEndPtr;
    searchMiliSeconds(miliStartPtr, miliEndPtr);
    size_t miliSecondsLen = miliEndPtr - miliStartPtr;

    XMLCh* retBuf = new XMLCh[10 + miliSecondsLen + 2];
    XMLCh* retPtr = retBuf;

    // 'hh:mm:ss'Z'    ('.'s+)?
    //      8    1
    //

    fillString(retPtr, Hour, 2);
    if (fValue[Hour] == 24)
    {
        *(retPtr - 2) = chDigit_0;
        *(retPtr - 1) = chDigit_0;
    }
    *retPtr++ = TIME_SEPARATOR;
    fillString(retPtr, Minute, 2);
    *retPtr++ = TIME_SEPARATOR;
    fillString(retPtr, Second, 2);

    if (miliSecondsLen)
    {
        *retPtr++ = chPeriod;
        XMLString::copyNString(retPtr, miliStartPtr, miliSecondsLen);
        retPtr += miliSecondsLen;
    }

    *retPtr++ = UTC_STD_CHAR;
    *retPtr = chNull;

    return retBuf;
}

void DateTime::fillString(XMLCh*& ptr, valueIndex ind, int expLen) const
{
    XMLCh strBuffer[16];
    assert(expLen < 16);
    XMLString::binToText(fValue[ind], strBuffer, expLen, 10);
    int   actualLen = (int) XMLString::stringLen(strBuffer);
    int   i;
    //append leading zeros
    for (i = 0; i < expLen - actualLen; i++)
    {
        *ptr++ = chDigit_0;
    }

    for (i = 0; i < actualLen; i++)
    {
        *ptr++ = strBuffer[i];
    }

}

int DateTime::fillYearString(XMLCh*& ptr, valueIndex ind) const
{
    XMLCh strBuffer[16];
    // let's hope we get no years of 15 digits...
    XMLString::binToText(fValue[ind], strBuffer, 15, 10);
    int   actualLen = (int) XMLString::stringLen(strBuffer);
    // don't forget that years can be negative...
    int negativeYear = 0;
    if(strBuffer[0] == chDash)
    {
        *ptr++ = strBuffer[0];
        negativeYear = 1;
    }
    int   i;
    //append leading zeros
    for (i = 0; i < 4 - actualLen+negativeYear; i++)
    {
        *ptr++ = chDigit_0;
    }

    for (i = negativeYear; i < actualLen; i++)
    {
        *ptr++ = strBuffer[i];
    }
    if(actualLen > 4)
        return actualLen-4;
    return 0;
}

/***
 *
 *   .check if the rawData has the mili second component
 *   .capture the substring
 *
 ***/
void DateTime::searchMiliSeconds(XMLCh*& miliStartPtr, XMLCh*& miliEndPtr) const
{
    miliStartPtr = miliEndPtr = 0;

    int milisec = XMLString::indexOf(fBuffer, MILISECOND_SEPARATOR);
    if (milisec == -1)
        return;

    miliStartPtr = fBuffer + milisec + 1;
    miliEndPtr   = miliStartPtr;
    while (*miliEndPtr)
    {
        if ((*miliEndPtr < chDigit_0) || (*miliEndPtr > chDigit_9))
            break;

        miliEndPtr++;
    }

    //remove trailing zeros
    while( *(miliEndPtr - 1) == chDigit_0)
        miliEndPtr--;

    return;
}

void DateTime::setBuffer(const XMLCh* const aString)
{
    reset();
    fEnd = (int) xercesc::XMLString::stringLen(aString);
    if (fEnd > 0) {
        if (fEnd > fBufferMaxLen) {
            delete[] fBuffer;
            fBufferMaxLen = fEnd + 8;
            fBuffer = new XMLCh[fBufferMaxLen+1];
        }
        memcpy(fBuffer, aString, (fEnd+1) * sizeof(XMLCh));
    }
}

void DateTime::reset()
{
    for ( int i=0; i < xercesc::XMLDateTime::TOTAL_SIZE; i++ )
        fValue[i] = 0;

    fMiliSecond   = 0;
    fHasTime      = false;
    fTimeZone[hh] = fTimeZone[mm] = 0;
    fStart = fEnd = 0;

    if (fBuffer)
        *fBuffer = 0;
}

void DateTime::copy(const DateTime& rhs)
{
    for ( int i = 0; i < xercesc::XMLDateTime::TOTAL_SIZE; i++ )
        fValue[i] = rhs.fValue[i];

    fMiliSecond   = rhs.fMiliSecond;
    fHasTime      = rhs.fHasTime;
    fTimeZone[hh] = rhs.fTimeZone[hh];
    fTimeZone[mm] = rhs.fTimeZone[mm];
    fStart = rhs.fStart;
    fEnd   = rhs.fEnd;

    if (fEnd > 0) {
        if (fEnd > fBufferMaxLen) {
            delete[] fBuffer;
            fBufferMaxLen = rhs.fBufferMaxLen;
            fBuffer = new XMLCh[fBufferMaxLen+1];
        }
        memcpy(fBuffer, rhs.fBuffer, (fEnd+1) * sizeof(XMLCh));
    }
}

void DateTime::initParser()
{
    fStart = 0;   // to ensure scan from the very first beginning
                  // in case the pointer is updated accidentally by someone else.
}

bool DateTime::isNormalized() const
{
    return (fValue[xercesc::XMLDateTime::utc] == xercesc::XMLDateTime::UTC_STD ? true : false);
}

int DateTime::getRetVal(int c1, int c2)
{
    if ((c1 == xercesc::XMLDateTime::LESS_THAN && c2 == xercesc::XMLDateTime::GREATER_THAN) ||
        (c1 == xercesc::XMLDateTime::GREATER_THAN && c2 == xercesc::XMLDateTime::LESS_THAN))
        return xercesc::XMLDateTime::INDETERMINATE;

    return (c1 != xercesc::XMLDateTime::INDETERMINATE) ? c1 : c2;
}
