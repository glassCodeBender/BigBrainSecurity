# -*- coding: utf-8 -*-
"""
@glassCodeBender
@Date: 5/24/2007
@Version: 1.0

Program Purpose: To filter a master file table to only include useful file
extensions and to search a MFT for all the occurences of certains viruses.

"""

import pandas as pd
# import numpy as np
import re 

class MFTFilter:
            
    def __init__(self):
        pass
    
    def main(self):
        df = pd.DataFrame()
        df = df.from_csv("MftDump_2015-10-29_01-27-48.csv", sep='|')
        # df_attack_date = df[df.index == '2013-12-03'] # Creates an extra df for the sake of reference
        ext_df = filter_by_exts(df)
        ext_df.to_csv('MFTfiltered_exts.csv', index=True)
                             
    """ 
    Filters a MFT csv file that was converted into a datafame to only include 
    relevant extensions.
    Param: DataFrame 
    Return: DataFrame - Filtered to only include relevant file extensions.
    """
    def filter_by_exts(self, df):
        
        pattern = r'.exe|.dll|.rar|.sys|.jar'
        regex1 = re.compile(pattern, flags=re.IGNORECASE)
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex1, regex = True)).any(axis=1)
        filt_df = df[df['mask'] == True]
    
        pattern2 = r'Create$|Entry$'
        regex2 = re.compile(pattern2, flags=re.IGNORECASE)
        filt_df['mask2'] = filt_df[['Type']].apply(lambda x: x.str.contains(regex2, regex = True)).any(axis=1)
        filtered_df = filt_df[filt_df['mask2'] == True]
        filtered_df.drop(['mask', 'mask2'], axis = 1, inplace = True)
        filtered_df.reset_index(level=0, inplace = True) # adds an integer index value.
        
        return filtered_df
    
    """ 
    Filters a MFT csv file that was converted into a datafame to only include the 
    occurences of certains viruses.
    Param: DataFrame 
    Return: DataFrame - Filtered to only include relevant file extensions.
    """
    def filter_by_virus(self, df):
        
        pattern = r'WinCon.SFX$|QueryStrategy.dll$|183187853b.exe$|dopdf-7.exe$|8.1.1_by_banjoo_(the_crack).jar$|DriverToolkitInstaller.exe$|driver_setup.exe$|driver_setup_2.exe$|SoftonicDownloader_for_winzip.exe$|tp4ui.dll$|e1y5032.sys$|e1y5132.sys$|nvunrm.exe$|187853b.exe$|5099850b.exe$|9852.exe$|QueryStrategy.dll$|Hibiki.dll$|ehsched.exe$|DriveToolkitInstaller[1].exe$'
        regex = re.compile(pattern, flags = re.IGNORECASE)                                                                                        
        df['mask'] = df[['Filename', 'Desc']].apply(lambda x: x.str.contains(regex, regex = True)).any(axis=1)
        virus_df = df[df['mask2'] == True]
        virus_df.drop('mask2', axis=1, inplace=True)  
        virus_df.to_csv('filterbyvirus.csv', index=True)                                              
        return virus_df                                                                                        

    if __name__ == '__main__':
        main() 
