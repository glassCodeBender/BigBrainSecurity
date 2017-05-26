"""
@Author: glassCodeBender
@Date: 5/25/2007
@Version: 1.0

Note: This program is far from complete. 

Program Purpose: To filter a master file table to only include useful file
extensions and to search a MFT for all the occurrences of certain viruses.
"""

import pandas as pd
# import numpy as np
import re
import sys
import os

class MFTCleaner:
    def __init__(self, imp_file = "MftDump_2015-10-29_01-27-48.csv", ext = '', vir_file = '', app_file = '', output_file = '',
                 start_date = '', end_date = '', start_time = '', end_time = '' ):
        self.__file = imp_file
        self.__ext = ext                 # accepts a txt file
        self.__virus_file = vir_file     # accepts a txt file
        self.__app_file = app_file       # accepts a txt file
        # these params probably should be converted using DateTime
        self.__start_date = start_date   # accepts a date to filter
        self.__end_date = end_date
        self.__start_time = start_time   # accepts a time to filter
        self.__end_time = end_time
        self.__output_file = output_file

    def main(self):
        df = pd.DataFrame()
        filename = self.__file
        df = df.from_csv(filename, sep='|')
        # df_attack_date = df[df.index == '2013-12-03'] # Creates an extra df for the sake of reference
        ext_df = self.filter_by_exts(df)
        ext_df.to_csv('MFTfiltered_exts.csv', index=True)

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
    def filter_by_exts(self, df):
        ext = self.__ext
        extension = self.read_file(ext)
        user_reg = self.update_reg(extension)

        if extension is not None:
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
    Filters a MFT csv file that was converted into a DataFrame to only include the occurrences of certain viruses.
    Param: DataFrame 
    Return: DataFrame - Filtered to only include relevant virus names. 
    """
    def filter_by_virus(self, df):
        virus_file = self.__virus_file
        outputf = self.__output_file
        virus_list = self.read_file(virus_file)
        user_reg = self.update_reg(virus_list)
        if user_reg is not None:
            pattern = r''+ user_reg
        else:
            pattern = r'WinCon.SFX$|QueryStrategy.dll$|183187853b.exe$|dopdf-7.exe$|8.1.1_by_banjoo_(the_crack).jar$|DriverToolkitInstaller.exe$|driver_setup.exe$|driver_setup_2.exe$|SoftonicDownloader_for_winzip.exe$|tp4ui.dll$|e1y5032.sys$|e1y5132.sys$|nvunrm.exe$|187853b.exe$|5099850b.exe$|9852.exe$|QueryStrategy.dll$|Hibiki.dll$|ehsched.exe$|DriveToolkitInstaller[1].exe$'
        regex = re.compile(pattern, flags=re.IGNORECASE)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex, regex=True)).any(axis=1)
        virus_df = df[df['mask2'] == True]
        virus_df.drop('mask2', axis=1, inplace=True)
        if outputf is not None:
            virus_df.to_csv(outputf, index=True)
        else:
            virus_df.to_csv('filterbyvirus.csv', index=True)
        return virus_df

    """ 
    Filters a MFT csv file that was converted into a DataFrame to only include the 
    occurrences of certain applications.
    Param: DataFrame 
    Return: DataFrame - Filtered to only include relevant applications. 
    """
    def filter_by_app(self, df):
        appfile = self.__app_file
        outputf = self.__output_file
        app_list = self.read_file(appfile)
        user_reg = self.update_reg(app_list)
        if user_reg is not None:
            pattern = r''+ user_reg
        else:
            pattern = r'regedit|powershell|'
        regex = re.compile(pattern, flags=re.IGNORECASE)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex, regex=True)).any(axis=1)
        app_df = df[df['mask2'] == True]
        app_df.drop('mask2', axis=1, inplace=True)
        if outputf is not None:
            app_df.to_csv(outputf, index=True)
        else:
            app_df.to_csv('filterbyapp.csv', index=True)
        return app_df

    """ 
    Filters a MFT csv file that was converted into a Dataframe to only include the 
    occurrences of certain dates or times
    Param: DataFrame 
    Return: DataFrame - Filtered to only include relevant virus names. 
    """
    def filter_by_dates(self, df):
        edate = self.__end_date
        sdate = self.__start_date
        pattern = r'Create$|Entry$'
        regex = re.compile(pattern, flags=re.IGNORECASE)
        filt_df['mask2'] = filt_df[['Type']].apply(lambda x: x.str.contains(regex2, regex=True)).any(axis=1)
        filtered_df = filt_df[filt_df['mask2'] == True]
        filtered_df.drop(['mask', 'mask2'], axis=1, inplace=True)
        # filtered_df.reset_index(level=0, inplace=True)  # adds an integer index value.
        return filtered_df

    if __name__ == '__main__':
        main()
