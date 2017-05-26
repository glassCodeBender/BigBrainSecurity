"""
@Author: glassCodeBender
@Date: 5/25/2007
@Version: 1.0

Program Purpose: To filter a master file table (MFT) to only include useful file
extensions and/or timeframes. 

Example Usage: 
~$ python cleanMFT.py -f MFTDump.csv -r filterlist.txt -d updated_mft.csv -s 6-21-2016 -e 6-23-2016'

For More Information Type the Following Command into the Terminal: 
~$ python cleanMFT.py --help 
      
Note: I can't test this program because the MFT dump I was working with has gone crazy. However, the core
components of the program work. I used them to filter a large MFT dump based on file extensions and virus names yesterday.
However, I haven't tested the concatenated regular expressions or the date time filtering yet.

"""

import pandas as pd
import re
import sys
import os
import argparse

class MFTCleaner:
    def __init__(self, imp_file, reg_file = '', output_file = '',
                 start_date = '', end_date = '', start_time = '', end_time = '' ):
        self.__file = imp_file
        self.__reg_file = reg_file       # accepts a txt file
        self.__start_date = start_date   # accepts a date to filter
        self.__end_date = end_date
        self.__start_time = start_time   # accepts a time to filter
        self.__end_time = end_time
        self.__output_file = output_file

    """ This is the main method of the program. """
    def main(self):
        output_file = self.__output_file
        mft_csv = self.__file
        df = pd.DataFrame()
        df = df.from_csv(mft_csv, sep='|')
        # df = df.from_csv("MftDump_2015-10-29_01-27-48.csv", sep='|')
        # df_attack_date = df[df.index == '2013-12-03'] # Creates an extra df for the sake of reference
        df = self.filter_by_dates(df)
        df = self.filter_by_filename(df)
        df.to_csv(output_file, index=True)

    """ 
    Read a file line by line and return a list with items in each line.
    @Param A Filename
    @Return A list 
    """
    def read_file(self, file):
        list = []
        with open(file) as f:
            for line in f:
                list.append(line)
        return list

    """ 
    Method to filter a list of words and concatenate them into a regex
    @Param List of words provided by user to alternative file.
    @Return String that will be concatenated to a regex. 
    """
    def update_reg(self, list):
        s = '|'
        new_reg = s.join(list)
        return new_reg

    """ 
    Filters a MFT csv file that was converted into a DataFrame to only include relevant extensions.
    @Param: DataFrame 
    @Return: DataFrame - Filtered to only include relevant file extensions. 
    """
    def filter_by_filename(self, df):
        reg_file = self.__reg_file
        reg_list = self.read_file(reg_file)
        user_reg = self.update_reg(reg_list)

        if user_reg is not None:
            pattern = r'' + user_reg
        else:
            pattern = r'.exe|.dll|.rar|.sys|.jar'

        regex1 = re.compile(pattern, flags=re.IGNORECASE)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex1, regex=True)).any(axis=1)
        filt_df = df[df['mask'] == True]

        pattern2 = r'Create$|Entry$'
        regex2 = re.compile(pattern2, flags=re.IGNORECASE)
        filt_df['mask2'] = filt_df[['Type']].apply(lambda x: x.str.contains(regex2, regex=True)).any(axis=1)
        filtered_df = filt_df[filt_df['mask2'] == True]
        filtered_df.drop(['mask', 'mask2'], axis=1, inplace=True)
        # filtered_df.reset_index(level=0, inplace=True)  # adds an integer index value.
        return filtered_df

    """ 
    Filters a MFT csv file that was converted into a Dataframe to only include the 
    occurrences of certain dates and/or times.
    @Param: DataFrame 
    @Return: DataFrame - Filtered to only include relevant virus names. 
    """
    def filter_by_dates(self, df):
        edate = self.__end_date
        sdate = self.__start_date
        etime = self.__end_time
        stime = self.__start_time

        if edate and sdate and etime and stime:
            s_stamp = pd.Timestamp(sdate + ' ' + stime)
            e_stamp = pd.Timestamp(edate + ' ' + etime)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate and edate and etime and not stime:
            s_stamp = pd.Timestamp(sdate)
            e_stamp = pd.Timestamp(edate + ' ' + etime)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate and edate and stime:
            s_stamp = pd.Timestamp(sdate + ' ' + stime)
            e_stamp = pd.Timestamp(edate)
            filtered_df = df[s_stamp:e_stamp]
        elif sdate:
            filtered_df = df[sdate:]
        elif edate:
            filtered_df = df[:edate]
        else:
            raise ValueError("You entered an invalid date to filter the table by or you did not include a date\n"
                             "to filter by. Please try again."
                             "\n\tExample Usage: $ python cleanMFT.py -f MFT.csv -r regex.csv -s 6-28-2015 -e 6-30-2015")
        return filtered_df

    """ Process command-line arguments. """
    if __name__ == '__main__':
        parser = argparse.ArgumentParser( add_help = True,
                                          description = 'cleanMFT.py filters master file tables and makes them more bearable to deal with.\n'
                                                        'The primary use of the program is to import a text file made up of values separated by new lines\n'
                                                        'that you can filter the program by. For example, you can import a text file made up of directories\n'
                                                        'you want included in the updated CSV file, file extensions (.exe, .dll, .sys), and/or programs (powershell).\n'
                                                        'cleanMFT.py will search the Master File Table CSV file and create a new CSV file that only includes matching rows.\n'
                                                        'Sample usage: '
                                                        '\n\n\t~$ python cleanMFT.py -f MFTDump.csv -r filterlist.txt -d updated_mft.csv -s 6-21-2016 -e 6-23-2016')
        parser.add_argument('-f', '--file', action = 'store', dest = 'file',
                            help = "Store the name of the MFT csv file you want converted.")
        parser.add_argument('-r', '--regex-file', action = 'store', dest = 'regex',
                            help = "Import a file made up of the names of files you want to include in the filtered table.\n"
                                   "\nThis option create a regular expression based on a text file with different values on each line."
                                   "\n\t-Examples: Create a text file with different file extensions on each line. (.dll, .exe)"
                                   "\n\t           Create a file made up of different virus names (WinCon.SFX, QueryStrategy.dll)"
                                   "\n\t           Create a file made up of a combination of directory names and/or files.")
        parser.add_argument('-d', '--dest', action = 'store', dest = 'file_dest',
                            default = ( str(os.getcwd()) + "/filteredcsvfile.csv" ),
                            help = "Store the name of the file you'd like the program to create.")
        parser.add_argument('-s', '--start-date', action = 'store', dest = 'start_date',
                            help = 'Enter a start date that you want to filter the table by.'
                                   'NOTE: If you DO NOT include an end date, the entire MFT table following\n'
                                   'the start date will be included in the CSV.'
                                   '\n\tExample format: 6-23-2014')
        parser.add_argument('-e', '--end-date', action = 'store', dest = 'end_date',
                            help = 'Enter an end date that you want to filter a table by.'
                                   'Note: If you do not include a start date, the entire MFT will'
                                   'be included in the CSV up until the end date.'
                                                                    '\n\tExample format: 6-27-2014')
        parser.add_argument('-t', '--start-time', action='store', dest = 'start_time',
                            help = 'Enter a start time to filter a table by in military time.'
                                                                         '\n\tExample format: 06:25')
        parser.add_argument('-u', '--end-time', action='store', dest = 'end_time',
                            help = 'Enter an end time to filter a table by in military time.'
                                                                         '\n\tExample format: 19:25')
        parser.add_argument('-v', '--verbose', action = 'store_true', help = 'Increase the verbosity of the program.')

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        # moving parsed arguments to local variables just to be safe
        args = parser.parse_args()
        file = args.file
        file_dest = args.file_dest
        sdate = args.start_date
        edate = args.end_date
        stime = args.start_time
        etime = args.end_time

        assert os.path.exists( str(os.getcwd()) + '/' + file )

        clean_MFT = MFTCleaner(file, file_dest, sdate, edate, stime, etime)
        clean_MFT.main()

        if args.verbose:
            assert isinstance(file_dest)
            print('Your csv file has been filtered and saved to %s' % file_dest)
