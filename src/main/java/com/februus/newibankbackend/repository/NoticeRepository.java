package com.februus.newibankbackend.repository;

import com.februus.newibankbackend.model.Notice;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NoticeRepository extends CrudRepository<Notice, Long> {

    /**
     * Using JPQL(with entity field) inside the @query instead of derived method name
     * Please fetch the notices where the current date is between notic_beg_dt and notic_end_dt
     * @return List of Notice
     */
    @Query(value="from Notice n where CURDATE() BETWEEN noticBegDt AND noticEndDt")
    List<Notice> findAllActiveNotices();
}
